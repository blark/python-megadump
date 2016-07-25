import time
import sys
import os
import struct
import collections
import pickle
from pprint import pprint
import serial
import click
import hexdump


SA302233 = {
    'password': [b'\xCC\xE3\xAA\xF0\x0F\x3C\xAE\xCE' for x in range(3)],
    'scratch': b'',
    'k_id': [],
    'mem': []
}

"""
Key = collections.namedtuple('Key', ['k_id', 'scratch', 'mem', 'pw'])

SA302233 = Key(k_id = [b'' for x in range(3)],
               scratch = {},
               mem = [b'' for x in range(3)],
               pw = [b'\xCC\xE3\xAA\xF0\x0F\x3C\xAE\xCE' for x in range(3)])
UNKNOWN = Key([b'' for x in range(3)],
              b'',
              [b'' for x in range(3)],
              [b'\xFF'*8 for x in range(3)])
"""

class SerialConnection(object):
    """
    Opens a serial connection to the Bus Pirate and sets up 1-Wire mode then
    turns on the power to the iButton and finds it using search rom command. 
    Also provides an object so we can send 1-Wire commands and get data from 
    the main function. 

    See docs at http://dangerousprototypes.com/blog/2009/10/20/bus-pirate-binary-1-wire-mode/

    """

    def __init__(self, serial_port):
        self.serial_port = serial_port
    
    def __enter__(self):
        # Open serial port
        try:
            self.ser = serial.Serial(port=self.serial_port, baudrate=115200)
        except serial.serialutil.SerialException:
            raise
        click.echo("\nConnected to Bus Pirate on {}...".format(self.serial_port))
        # Put the Bus Pirate in bit-bang mode
        click.echo('Enabling Bus Pirate bit-bang mode...', nl=False)
        while self.ser.in_waiting is 0:
            self.ser.write(b'\x00')
            self.ser.flush()
            time.sleep(.1)
        resp = self.ser.read_all().decode()
        if resp == 'BBIO1':
            click.secho('success.', fg='green', bold=True)
        else:
            click.echo('Received unknown response from Bus Pirate: '
                       '{}'.format(resp))
            sys.exit()
        # Enable 1-Wire mode
        click.echo('Enabling 1-Wire mode...', nl=False)
        self.cmd(b'\x04', b'1W01')
        # Enable power supply
        click.echo('Turning on VREG...', nl=False)
        self.cmd(b'\x48', b'\x01')
        # Test if iButton is present
        click.echo('Checking for 1-Wire device...', nl=False)
        self.ser.write(b"\x08")
        time.sleep(.2)
        resp = self.ser.read_all()[1:9]
        if resp == b'\xFF'*8:
            click.echo('no devices discovered on 1-Wire bus. Check your '
                       'wiring...')
            sys.exit()
        else:
            click.echo('device found, mac: ', nl=False)
            click.secho('{}'.format(resp.hex()), fg='red', bold=True)
        return self

    def cmd(self, payload, resp):
        """
        Sends data to the bus pirate and waits for a response. If the response
        isn't correct, throws an error and exits the program.
        """
        self.ser.write(payload)
        self.ser.flush()
        time.sleep(.1)
        cmd_resp = self.ser.read_all()
        if (cmd_resp != resp):
            click.echo('Unexpected response: {}'.format(cmd_resp))
            sys.exit()
        else:
            click.secho('success.', fg='green', bold=True)
            return (True, cmd_resp)
        
    def __exit__(self, exception_type, exception_value, traceback):
        click.echo("Powering off VREG and closing serial connection...", nl=False)
        self.cmd(b'\x40', b'\x01')
        self.ser.close()
    
def read_bytes(con, n):
    """
    Reads n bytes from the 1-Wire bus.
    """
    con.ser.write(b'\x04'*n)
    time.sleep(.2)
    resp = con.ser.read_all()
    return resp

def cmd_data(con, payload, resp_size, rst=True):
    """
    Sends payload to the 1-Wire bus and returns a response of resp_size.
    """
    # assemble the command
    reset_bus = b'\x02'
    num_bytes = struct.pack("B", (len(payload)-1)+0x10)
    if rst:
        con.ser.write(reset_bus)
    con.ser.write(num_bytes)
    con.ser.write(payload)
    time.sleep(.2)
    #print("DEBUG:", con.ser.read_all())
    con.ser.reset_input_buffer()
    if resp_size == 0:
        return None
    else:
        # read the response from the 1-Wire bus
        return read_bytes(con, resp_size)

@click.command()
@click.argument('key_rev', default='SA302233', required=False)
@click.argument('serial_port', default='/dev/ttyACM0', required=False)
@click.option('--write', '-w', is_flag=True, help='Write key to iButton.')

def main(serial_port, key_rev, write):
    """Megadump dumps and writes Megatouch iButton keys"""
    with SerialConnection(serial_port) as bp:
        # Set up some variables
        ibutton = b''
        key_file = (key_rev+'.pickle')

        if write:
            # Write data to iButton
            click.secho('\nWriting key from {}.\n'.format(key_file), fg='blue')
            k = pickle.load(open(key_file, "rb"))
            pprint(k)
            #
            # TODO: Insert code to write keys here.
            #

        else:
            # Dump the iButton key contents
            try:
                k = eval(key_rev)
            except NameError:
                k = UNKNOWN

            click.secho('\nDumping contents of key.\n', fg='blue')
            # Send commands reset (CC), read scratch (69), start addr,
            # inverted start addr. Then rec 64 bytes. 
            k['scratch'] = cmd_data(bp, b'\xCC\x69\xC0\x3F', 64)
            click.echo('Scratchpad:')
            hexdump.hexdump(k.get('scratch'))
            click.echo()

            for idx, n in enumerate([0,64,128]):
                # Calculate memory ID to send to iButton
                mem_id = struct.pack("B", (n+16))
                mem_id_oc = struct.pack("B", (n+16) ^ 0xFF)

                # Send commands reset (CC), read subkey (69), key+start addr,
                # key+start addr inverted. Rec. 8 byte key ID in response.
                k['k_id'].append(cmd_data(bp, b'\xCC\x66'+mem_id+mem_id_oc, 8))
                click.echo('Subkey {} id 0x{} ({}):'.format(idx, k['k_id'][idx].hex(), k['k_id'][idx]))
                # Send password then rec. 48 bytes from secure memory
                k['mem'].append(cmd_data(bp, k["password"][idx], 48, rst=False))
                hexdump.hexdump(k['mem'][idx])
                click.echo()

            # write key information to file
            if os.path.isfile(key_file):
                click.confirm('Dump file already exists, overwrite it?', abort=True)
            f = open(key_file, 'wb')
            pickle.dump(k, f)
            f.close()
            click.echo('Wrote key to {}/{}'.format(os.getcwd(), key_file))

    print()





"""
      iButton binary dump format:

                                      1  1  1  1  1  1
        0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |  ID_0                 |  ID_1                 |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |  ID_2                 |  PW_0                 |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |  PW_1                 |  PW_2                 |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |  SCRATCHPAD (64 bytes)                        |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |  SUBKEY_00 (48 bytes)                         |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |  SUBKEY_01 (48 bytes)                         |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
      |  SUBKEY_10 (48 bytes)                         |
      +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
"""
