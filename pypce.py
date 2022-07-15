# Initiated in 2022 by Jouni 'Mr.Spiv' Korhonen
# ---------------------------------------------
#
# This is free and unencumbered software released into the public domain.
# 
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
# 
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
# 
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
# 
# For more information, please refer to <http://unlicense.org/>

import serial
import serial.tools.list_ports

import tkinter as tk
from tkinter import Variable, ttk
from tkinter import font
from tkinter import filedialog as fd

import argparse
import sys

"""Note! For time being all classes are within a single file.
   This is just to keep things very simple.
   In the future the pce_flasher class will be a separate file
   and the Gui class another file.
"""

# Mighty decorator to check if opening the serial port succeeded..
# This works only for methods that return integers..
def check_is_open(func):
    """A decorator to check if __init__() managed to create object properly.
    
       This decorator works only with methods of pce_flasher class that 
       return integer value. In a case the __init__() had on issue i.e., 
       likely instantiating the serial.Serial failed then pce_flasher.INIT_FAILED
       is returned without calling the actual method.
    """

    def check(self,*args,**kwargs):
        if (self.is_open() is False):
            return pce_flasher.INIT_ERROR
        else:
            return func(self,*args,**kwargs)

    return check

#
#
class pce_flasher(object):
    """A wrapper to serial module with knowledge of the GamingEnterpriseInc 8Mbit Flash HuCard v1.1.
    """

    # Version information
    VERSION_MAJOR = 0
    VERSION_MINOR = 1

    # Support class for GamingEnterpriseInc.com 8Mbit Flash HuCard v1.1
    VID = 0x0403
    PID = 0x6001
    BAUD = 250000

    REQSIZE = 256+5
    REPSIZE = 6
    DATSIZE = 256
    WTOUT = 80
    RTOUT = 80

    # Verify response return codes
    REP_OK = 0
    REP_HEADER_ERROR = -1
    REP_CHECKSUM_ERROR = -2
    REP_RESPONSE_ERROR = -3
    REP_ADDRESS_ERROR = -4

    # Flashing ROM response codes
    FLASH_OK = 0
    FLASH_WRITE_TIMEOUT_ERROR = -5   # Write timed out
    FLASH_RESPONSE_ERROR = -6
    FLASH_CANCELLED_ERROR = -7
    FLASH_WRITE_ERROR = -8          # generic error i.e. wrote less that requested

    # Other errors..
    INIT_OK = 0
    INIT_ERROR = -100

    #
    def __init__(self,port):
        """Initialize the pce_flasher object for a specific TTY/COM port.
        
           Parameters:
             port (str): Full path for a TTY/COM device to open.

           Note:
           If opening the device fails the exception is caught and the
           pce_flasher object is created as partially initialized. The
           following methods in this case will return pce_flasher.INIT_ERROR
           - make_pkt()
           - send_pkt()
           - flash_rom()
        """

        try:
            self.ser = serial.Serial(port,
                baudrate=pce_flasher.BAUD,
                bytesize=serial.EIGHTBITS,
                stopbits=serial.STOPBITS_ONE,
                timeout=pce_flasher.RTOUT,
                write_timeout=pce_flasher.WTOUT
            )
        except Exception as e:
            self.ser = None
            return

        self.buf = bytearray(pce_flasher.REQSIZE)

    #
    def __enter__(self):
        """For use 'with' statement."""
        return self

    #
    def __exit__(self,type,value,traceback):
        """For use 'with' statement."""
        self.close()

    #
    def is_open(self):
        """Check if pce_flasher object managed to initialize itself properly."""

        if (self.ser):
            return self.ser.is_open
        else:
            return False

    #
    def close(self):
        """Close the pce_flasher object. This is safe to call in all cases."""
        if (self.ser):
            self.ser.close()
            self.ser = None
            self.buf = None

    #
    @staticmethod
    def find_usb_coms(vid: int =VID,pid: int =PID) -> tuple:
        """Return a list of ports found in the system and an index to flash card device.
        
           Parameters:
             vid (int): VID of the Flash Card. Defaults to pce_flasher.VID.
             pid (int): PID of the Flash Card. Defaults to pce_flasher.PID.

           Return:
             ports (list), port_index (int): List of found ports and an index to the
               GamingEnterpriseInc 8Mbit Flash HuCard v1.1 if found. If no card is 
               found the port_index is 0. Note that if the card is on index 0 then
               0 is also returned so error checking must be based on the ports list,
               which is empty if no port is found.
        """

        ports = serial.tools.list_ports.comports(include_links=True)
        # Maybe we should return -1 is no maching port is found..?
        port_index = 0
        cnt = 0

        for port in ports:
            if (vid == port.vid and pid == port.pid):
                port_index = cnt 

            cnt += 1

        return ports,port_index

    #
    def get_buf(self) -> bytearray:
        return self.buf
    
    #
    def calc_chksum(self,pkt: bytearray, request: bool =True) -> int:
        """Calculate the GamingEnterpriseInc 8Mbit Flash HuCard v1.1 packet checksum.
        
        Parameters:
          pkt (bytearray): The packet to calculate the checksum over.
          request (bool): True if 'pkt' contains a request packet with data payload.
                          False if 'pkt' contains a reply packet.

        return:
          sum (int): Checksum of the 'pkt'.
        """

        sum = int(0)
        len = pce_flasher.REQSIZE-1 if request else pce_flasher.REPSIZE-1 

        for i in range(1,len):
            sum += pkt[i]

        sum = sum & 0xff

        return sum

    #
    def verify_response(self,pkt: bytes,addr: int=None) -> int:
        """Verify the validity of the response packet from the GamingEnterpriseInc 8Mbit Flash HuCard v1.1.

           Parameters:
             pkt (bytes): The 6 octet reply packet from the card.
             addr (int): If present (i.e. no None) then also verify the response packet against
               the given address in the 'addr'.

           Return:
            Response status (int): 
        """
        
        # Check response length
        if (pkt.__len__() != pce_flasher.REPSIZE):
            return pce_flasher.REP_RESPONSE_ERROR

        # Is this response?
        if (pkt[0] != 0xa5):
            return pce_flasher.REP_HEADER_ERROR
        
        chksum = self.calc_chksum(pkt,request=False)

        # Checksums match?
        if (pkt[5] != chksum):
            return pce_flasher.REP_CHECKSUM_ERROR

        # OK or Error response
        if (pkt[4] != 0x01):
            return pce_flasher.REP_RESPONSE_ERROR

        # verify address
        if (addr is not None):
            if (not (pkt[1] == (addr) & 0xff) and
                    (pkt[2] == (addr >> 8) & 0xff) and
                    (pkt[3] == (addr >> 16) & 0xff)):
                return pce_flasher.REP_ADDRESS_ERROR
        
        return pce_flasher.REP_OK

    #
    @check_is_open
    def make_pkt(self,addr: int, dat: bytearray,pos: int,len: int) -> int:
        """Construct a data packet to be sent to GamingEnterpriseInc 8Mbit Flash HuCard v1.1.
        
           Parameters:
             addr (int): Address of the data in the flash card.
             dat (bytearray): Byte buffer holding the data. It can be larger than the 'len'
               of bytes to send.
             pos (int): Position of the data to send in the 'dat'.
             len (int): Length of the actual data in the 'dat'. This can be shorter or longer than
               the accepted 256 bytes. In a case the 'len' is shorted the rest of the packet is
               padded with 0xff and in a case the 'len' is greater than 256 thrn the packet size
               is capped to 256.

           Return:
             Status code (int):  pce_flasher.INIT_OK if successful and an error otherwise.
               Currently pce_flasher.INIT_ERROR is the only possible returned error.
        """

        self.buf[0] = 0x5a
        # assume that 'addr' is little endian from memory..
        self.buf[1] = (addr) & 0xff
        self.buf[2] = (addr >> 8) & 0xff
        self.buf[3] = (addr >> 16) & 0xff

        i = 0

        if (len > pce_flasher.DATSIZE):
            len = pce_flasher.DATSIZE

        while (i < len):
            self.buf[4+i] = dat[pos+i]
            i = i + 1

        while (i < pce_flasher.DATSIZE):
            self.buf[4+i] = 0xff
            i = i + 1

        self.buf[4+pce_flasher.DATSIZE] = self.calc_chksum(self.buf,True)
        return pce_flasher.INIT_OK

    #
    @check_is_open
    def send_pkt(self) -> int:
        """Send a constructed packet to the flash card.
        
           Parameters:
             None
             
           Return:
             Return value (int): pce_flasher.DATSIZE is send was successful. Otherwise
               either pce_flasher.FLASH_WRITE_TIMEOUT_ERROR or pce_flasher.FLASH_WRITE_ERROR
               if the error origiated form the serial. Other exceptions are reraised."""
        try:
            len = self.ser.write(self.buf)
            #print(f"Wrote {len} bytes")
        except serial.SerialTimeoutException:
            return pce_flasher.FLASH_WRITE_TIMEOUT_ERROR
        except Exception as e:
            raise e

        if (len != pce_flasher.REQSIZE):
            return pce_flasher.FLASH_WRITE_ERROR

        # Sent data is alwasy pce_flasher.DATSIZE
        return pce_flasher.DATSIZE

    #
    def recv_pkt(self,len: int) -> bytes:
        # this may block..
        return self.ser.read(len)


    # Flash loop with a callback..
    @check_is_open
    def flash_rom(self,rom: bytearray, addr: int, callback) -> int:
        """Flash an arbitrary buffer into the flash card.
        
           Parameters:
             rom (bytearray): A buffer to be flashed. Total bytes flashed are
               always rounded to the next full pce_flasher.DATSIZE (i.e. 256 bytes).

              addr (int): The address in the flash card where the data is placed.
                In practise the address is always incremented by pce_flasher.DATSIZE
                (i.e. 256) bytes.

              callback (function): A callback function that is called before every
                flashed packet. If the function returns True then flashing is aborted.
                The function has the following prototype:

                callback(self, rom_pos: int, rom_len: int) -> bool 

           Return:
             rom_pos (int): Index within the input 'rom' or negative in case of an
               error. Note that the returned rom_pos may be rounded up to the next
               pce_flasher.DATSIZE (i.e. 256) bytes making it greater than the
               input rom length.
        """
        rom_len = rom.__len__()
        rom_pos = 0

        while (rom_pos < rom_len):
            if (callback(rom_pos,rom_len)):
                return pce_flasher.FLASH_CANCELLED_ERROR

            self.make_pkt(addr,rom,rom_pos,rom_len-rom_pos)
            len = self.send_pkt()

            if (len == pce_flasher.FLASH_WRITE_TIMEOUT_ERROR):
                return len

            reply_pkt = self.recv_pkt(pce_flasher.REPSIZE)
            reply = self.verify_response(reply_pkt,addr)

            if (reply != pce_flasher.REP_OK):
                return reply

            if (len < 0):
                return len

            rom_pos = rom_pos + len
            addr = addr + len

        return rom_pos

    #
    def dumphdr(self,buf):
        print(f"Byte 1: {buf[0]}")
        print(f"Byte 2: {buf[1]}")
        print(f"Byte 3: {buf[2]}")
        print(f"Byte 4: {buf[3]}")
        print(f"Byte 5: {buf[4]}")
        print(f"Byte 6: {buf[5]}")


# Just a test of a Button class that could be used to carry
# button specific data easily to callback functions.
# The object itself is passed to the callback.
class dataButton(ttk.Button):
    def cb(self):
        self.cb_func(self)

    def __init__(self,root,cb,**kwargs):
        self.cb_func = cb
        self.root = root
        self.args = kwargs
        super().__init__(root,**kwargs,command=self.cb)
        
#
#
class Con(object):
    def CONOutput(self,s: str):
        print(s,end="")

    def __init__(self,**kwargs):
       # Following finctions and 'preferences' are not mandatory 
        if ("output" in kwargs):
            self.output = kwargs["output"]
        else:
            self.output =  self.CONOutput

        if ("args" in kwargs):
            self.args = kwargs["args"]
        else:
            raise RuntimeError("commandline 'args' missing") 

    #
    def prepare_rom(self, rom: bytes) -> bytearray:
        offset = pce_tools.remove_rom_header_pos(rom)

        if (offset < 0):
            # Something went wrong..
            self.output(f"ROM Error: {offset}.\n")
            return None

        # attempt to remove ROM header
        if (self.args.remove_hdr):
            if (offset > 0):
                self.output(f"Header removed ({offset} bytes).\n")
        else:
            offset = 0

        # Make a mutable copy.. and remove possible found header.
        prepared_rom = bytearray(rom[offset:])

        # try patching USA region check..
        if (self.args.patch_usa):
            offset = pce_tools.patch_usa_rom(prepared_rom,True)

            if (offset < 0):
                if (offset == pce_tools.USAPATCHNOTFOUND):
                    self.output(f"No USA region check code found.\n")
                else:
                    self.output(f"Patching USA region check failed: {offset}.\n")
            else:
                self.output(f"USA region check patched at offset {offset:04x}.\n")

        # The cart is US by default --> make a Japanese ROM
        if (self.args.make_jpn):
            pce_tools.reverse_rom_bytes(prepared_rom)
            self.output(f"ROM prepared for Japanese PC Engines.\n")

        # return mutable version of the ROM..
        return prepared_rom

    def update_progress(self,current: int,total: int) -> bool:
        if (current > total):
            current = total

        self.output(f"\rFlashing {current:7d}/{total:d} bytes\r")

        # We could check for CTRL-C here.. but..
        return False

    def run(self):
        if (self.args.input is None):
            self.output(f"Error: no input ROM file given.\n")
            sys.exit(-1)

        rom = file_tools.load_binary_file(self.args.input)

        if (rom is None):
            self.output(f"Error: failed to load '{self.args.input}.'\n")
            sys.exit(-1)

        prepared_rom = self.prepare_rom(rom)

        if (prepared_rom is None):
            sys.exit(-1)

        #
        if (self.args.output is not None):
            self.output(f"Saving '{self.args.output}'.\n")
            written = file_tools.save_binary_file(self.args.output,prepared_rom)

            if (written <= 0):
                self.output(f"Saving failed.\n")
                sys.exit(-1)

            self.output(f"Saved '{written}' bytes.\n")

        #
        if (self.args.flash_rom):
            if (self.args.port is not None):
                device = self.args.port
            else:
                port_pairs,port_index = pce_flasher.find_usb_coms()

                if (port_pairs.__len__() > 0):
                    device = port_pairs[port_index].device
                else:
                    device = None
                    self.output("No flasher found.\n")

            #
            pos = 0
            len = prepared_rom.__len__()

            with pce_flasher(device) as pf:
                ret = pf.flash_rom(prepared_rom,0x0000000,self.update_progress)

            if (ret < 0):
                self.output(f"Flashing failed: {ret}\n")    
            else:
                self.output(f"Flashed {ret} bytes successfully.\n")

#
#
class file_tools(object):
    @staticmethod
    def load_binary_file(filename: str) -> bytearray:
        buf = None

        with open(filename,"rb") as fh:
            # The returned buffer is immutable..
            buf = bytes(fh.read())

        return buf

    @staticmethod
    def save_binary_file(filename: str,rom: bytearray) -> int:
        with open(filename,"wb") as fh:
            # The returned buffer is immutable..
            len = fh.write(rom)

        return len

#
#
class pce_tools(object):
    patchCode = b'\xad\x00\x10\x29\x40\xf0'
    OK=0
    NOROMHEADERFOUND=-1
    ROMTOOSMALL=-2
    USAPATCHNOTFOUND=-3
    ROMALIGNMENTERROR=-4

    @staticmethod
    def remove_rom_header_pos(rom: bytearray) -> int:
        """Find number of bytes to skip if the header is present in the ROM.
        
           The used algorithm is rather trivial and therefore not necessarily
           too fail safe. If the total rom length is not a multiple on 8K, then
           take the modulo 8K (i.e. 8192) of the rom size. Use the reminder of the
           modulo as the shift (i.e. header size) and then check if the bank 0
           reset vector contains a jump into page 7.. this is pretty much must
           since the back 0 is mapped to page 7 after a reset.
           
           Parameters:
             rom (bytearray): Rom file to check. The length must be at least 8K.
             
           Return:
             status code (int): 0 if no header found, negative if an error (not
               fatal) took place or the size of the found header (i.e. the number
               of bytes to skip from the beginning of the rom file).
        """

        romsize = rom.__len__()
        shft = romsize & 0x1fff

        if (romsize < 0x2000):
            # Cannot handle ROMs smaller than one page..
            return pce_tools.ROMTOOSMALL
        
        if (romsize & 0x1ffff == 0):
            # 1Mbit even..
            return pce_tools.OK

        if (rom[shft + 0x1fff] >= 0xe0):
            return shft
        
        # generic error..
        return pce_tools.OK

    @staticmethod
    def patch_usa_rom(rom: bytearray, patch: bool) -> int:
        """Check or patch a typical USA region protection code in the ROM."""

        # search only the first 8K of the rom for the following code:
        #
        #  LDA $1000	; AD 00 10
        #  AND #$40    ; 29 40
        #  BEQ ...     ; F0
        #
        # which is the most common USA region check..

        romlen = rom.__len__()
        n = 0
	
        while (n < 8192 and n < romlen):
            m = 1
            
            if (rom[n] == pce_tools.patchCode[0]):
                while (m < 6 and n+m < romlen):
                    if (rom[n+m] != pce_tools.patchCode[m]):
                        break
                    else:
                        m = m +1
                    
                if (m == 6):
                    if (patch):
                        # Only patch if asked to do so..
                        rom[n+5] = 0x80
                    
                    return n

            n += m
        
        return pce_tools.USAPATCHNOTFOUND

    @staticmethod
    def bit_reverse_byte(i: int) -> int:
        # Based on https://stackoverflow.com/questions/12681945/reversing-bits-of-python-integer
        return int(format(i,"08b")[::-1], 2)

    @staticmethod
    def reverse_rom_bytes(rom: bytearray):
        for n in range(rom.__len__()):
            rom[n] = pce_tools.bit_reverse_byte(rom[n])


#
# 
class Gui(tk.Tk):
    """A tkinter-based GUI for the GamingEnterpriseInc.com 8Mbit Flash HuCard v1.1 programming
    
       For more information see http://www.gamingenterprisesinc.com/Flash_HuCard/
    """
    # GUI version information
    VERSION_MAJOR = 0
    VERSION_MINOR = 1
    
    #Other GUI Constants
    CONSOLE_WIDTH = 40

    #
    def USBcombo_update(self):
        self.port_pairs,self.port_index = pce_flasher.find_usb_coms()
        if (self.port_pairs.__len__() > 0):
            self.USBcombo["values"] = [port.device for port in self.port_pairs]
            self.USBcombo.current(self.port_index) #set the selected item
        else:
            self.USBcombo["values"] = ["No flasher found"]
            self.USBcombo.current(0) #set the selected item
            self.port_pairs = None

        self.USBcombo["state"] = "readonly"

    #
    def prepare_rom(self, rom: bytes) -> bytearray:
        offset = pce_tools.remove_rom_header_pos(rom)

        if (offset < 0):
            # Something went wrong..
            self.output(f"ROM Error: {offset}.\n")
            return None

        # attempt to remove ROM header
        if (self.chk_remove_state.get()):
            if (offset > 0):
                self.output(f"Header removed ({offset} bytes).\n")
        else:
            offset = 0

        # Make a mutable copy.. and remove possible found header.
        prepared_rom = bytearray(rom[offset:])

        # try patching USA region check..
        if (self.chk_region_state.get()):
            offset = pce_tools.patch_usa_rom(prepared_rom,True)

            if (offset < 0):
                if (offset == pce_tools.USAPATCHNOTFOUND):
                    self.output(f"No USA region check code found.\n")
                else:
                    self.output(f"Patching USA region check failed: {offset}.\n")
            else:
                self.output(f"USA region check patched at offset {offset:04x}.\n")

        # The cart is US by default --> make a Japanese ROM
        if (self.chk_jpn_state.get()):
            pce_tools.reverse_rom_bytes(prepared_rom)
            self.output(f"ROM prepared for Japanese PC Engines.\n")

        # return mutable version of the ROM..
        return prepared_rom

    #
    def load_rom_callback(self):
        self.USBcombo_update()

        filename = fd.askopenfilename(
        #filename = fd.asksaveasfilename(
            title="Select a ROM file",
            initialdir=".",
            # These does not seem to work in my OSX 10.13.6
            #filetypes=(
            #    ("PCE ROMs", "*.pce"),
            #    ("All files", "*.*")
            #)
        )

        if (filename == ""):
            self.output("No ROM selected.\n")
            return

        self.output(f"Loading '{filename}'.\n")
        self.rom = file_tools.load_binary_file(filename)

        if (self.rom is None):
            self.output(f"Loading failed.\n")
            return

        len = self.rom.__len__()
        self.output(f"Loaded '{len}' bytes.\n")

    #
    def flash_rom_callback(self):
        if (self.rom is None):
            self.output(f"No ROM file loaded.\n")
            return
        
        if (self.port_pairs is None):
            self.output(f"No USB COM found.\n")
            return
        
        flashable_rom = self.prepare_rom(self.rom)

        if (flashable_rom is None):
            # This ROM file is not usable..
            self.rom = None
            return

        self.init_progress_bar()

        with pce_flasher(self.USBcombo.get()) as pf:
            ret = pf.flash_rom(flashable_rom,0x0000000,self.update_progress_bar)

        self.close_progress_bar()

        if (ret < 0):
            if (self.progress_cancelled):
                self.output("Flashing cancelled..\n")
            else:
                self.output(f"Flashing failed: {ret}.\n")
            
            return

        self.output(f"Flashed {ret} bytes successfully.\n")

    #
    def save_rom_callback(self):
        if (self.rom is None):
            self.output(f"No ROM file loaded.\n")
            return
        
        saveable_rom = self.prepare_rom(self.rom)

        if (saveable_rom is None):
            # This ROM file is not usable..
            self.rom = None
            return

        filename = fd.asksaveasfilename(
            title="Select a file to save the ROM",
            initialdir=".",
            # These does not seem to work in my OSX 10.13.6
            #filetypes=(
            #    ("PCE ROMs", "*.pce"),
            #    ("All files", "*.*")
            #)
        )

        if (filename == ""):
            self.output("No ROM file name selected.\n")
            return

        self.output(f"Saving '{filename}.'\n")
        written = file_tools.save_binary_file(filename,saveable_rom)

        if (written <= 0):
            self.output(f"Saving failed.\n")
            return

        self.output(f"Saved '{written}' bytes.\n")

    #
    def GUIOutput(self,s: str):
        self.console.insert(tk.END,s)

        while (self.console.get('1.0',tk.END).__len__() > 2 * (self.console_size)):
            self.console.delete("1.0","2.0")

        self.console.see(tk.END)

    #
    def update_progress_bar(self,current: int,total: int) -> bool:
        if (current > total):
            current = total

        self.pb['value'] = 100 * (current / total)
        self.update()
        return self.progress_cancelled

    #
    def cancel_progress_bar(self):
        self.progress_cancelled = True

    #
    def init_progress_bar(self) -> object:
        self.pbw = tk.Toplevel(self)
        self.pbw.title("Flashing a ROM..")
        self.pbw.grab_set()
        self.pbw.protocol("WM_DELETE_WINDOW",self.cancel_progress_bar)

        self.progress_cancelled = False

        # progressbar, "determinate" i.e. we know progress explicitly
        self.pb = ttk.Progressbar(self.pbw, orient="horizontal",mode="determinate",length=320)

        # place the progressbar
        self.pb.grid(column=0, row=1, padx=10, pady=20)

        # cancel button
        cancel_button = ttk.Button(self.pbw, text="Cancel", command=self.cancel_progress_bar)
        cancel_button.grid(column=0, row=2, padx=10, pady=10, sticky=tk.S)

        return self.pbw

    #
    def close_progress_bar(self):
        self.pb.stop()
        self.pbw.destroy()

    #
    def __init__(self,**kwargs):
        """Build the GUI layout and prepare all callback functions & variables."""
        
        # Create Tk instance and self will be the "root"
        super().__init__()

        # Our "in memory" ROM file
        self.rom = None

       # Following finctions and 'preferences' are not mandatory 
        if ("output" in kwargs):
            self.output = kwargs["output"]
        else:
            self.output =  self.GUIOutput

        # Build GUI
        self.resizable(False,False)
        self.title(f"PCE Flash Tool v{Gui.VERSION_MAJOR}.{Gui.VERSION_MINOR}")

        #self.lift()
        #self.attributes("-topmost", 1)
        #self.attributes("-topmost", 0)

        # Three frames.. and separators
        self.action_frm = ttk.LabelFrame(self,text="Actions")
        self.action_frm.grid(column=0,row=0,sticky=tk.EW,ipadx=1,ipady=1)

        self.prefs_frm = ttk.LabelFrame(self,text="Settings")
        self.prefs_frm.grid(column=0,row=2,sticky=tk.EW,ipadx=1,ipady=1)

        self.sep1 = ttk.Separator(self, orient='horizontal')
        self.sep1.grid(column=0,row=1,sticky=tk.EW,pady=1)

        self.text_frm = ttk.LabelFrame(self,text="Console Output")
        self.text_frm.grid(column=2,rowspan=3,row=0,sticky=tk.NS,ipadx=1,ipady=1)

        self.sep2 = ttk.Separator(self, orient='vertical')
        self.sep2.grid(column=1,row=0,rowspan=3,sticky=tk.NS,padx=1)

        # Console with scrollbar for text output.. the height will be fixed later
        # scrollbar based on https://stackoverflow.com/questions/30669015/autoscroll-of-text-and-scrollbar-in-python-text-box
        # We attempt to get a fixed size very typical font for outout
        font_metrics = tk.font.nametofont('TkDefaultFont').metrics()
        font_height = font_metrics["linespace"]
        font_ascent = font_metrics["ascent"]
        self.console = tk.Text(self.text_frm,width=Gui.CONSOLE_WIDTH,height=1,font =("Courier",font_ascent))
        self.vsb = tk.Scrollbar(self.text_frm, orient="vertical", command=self.console.yview)
        self.console.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right", fill="y")
        self.console.pack(side="left", fill="both", expand=True)
        
        # 'Load ROM'
        self.load_rom_button = ttk.Button(self.action_frm,command=self.load_rom_callback,text="Load ROM", state="enabled")
        self.load_rom_button.grid(column=0,row=0,sticky=tk.EW)

        # "Flash ROM"
        self.flash_rom_button = ttk.Button(self.action_frm,text="Flash ROM", state="enabled",command=self.flash_rom_callback)
        self.flash_rom_button.grid(column=0,row=1,sticky=tk.EW)
    
        # "Write ROM"
        self.save_rom_button = ttk.Button(self.action_frm,text="Save ROM", state="enabled",command=self.save_rom_callback)
        self.save_rom_button.grid(column=0,row=2,sticky=tk.EW)

        # Check button for "remove region protection"
        self.chk_region_state = tk.BooleanVar()
        self.chk_region_state.set(True)
        self.chk_region = ttk.Checkbutton(self.prefs_frm,text="Remove US region protection",
            var=self.chk_region_state,onvalue=True,offvalue=False,state="enabled")
        self.chk_region.grid(column=0,row=0,sticky=tk.EW)

        self.chk_remove_state = tk.BooleanVar()
        self.chk_remove_state.set(True)
        self.chk_remove = ttk.Checkbutton(self.prefs_frm,text="Remove ROM header",#width=26,
            var=self.chk_remove_state,onvalue=True,offvalue=False,state="enabled")
        self.chk_remove.grid(column=0,row=1,sticky=tk.EW)
    
        self.chk_jpn_state = tk.BooleanVar()
        self.chk_jpn_state.set(False)
        self.chk_jpn = ttk.Checkbutton(self.prefs_frm,text="JPN PC-Engine",#width=26,
            var=self.chk_jpn_state, onvalue=True,offvalue=False,state="enabled")
        self.chk_jpn.grid(column=0,row=2,sticky=tk.EW)
    
        # Combobox for USB port for the flasher..
        self.USBcombo = ttk.Combobox(self.prefs_frm)
        self.USBcombo["state"] = "disabled"
        self.USBcombo["values"] = ["No Flasher searched"]
        self.USBcombo.current(0)
        self.USBcombo.grid(column=0, row=3,sticky=tk.EW)

        # Force update so that we get the sizes properly from the layout..
        self.update()

        # Now fix the console output window height
        frame_height = self.text_frm.winfo_height()
        self.console.configure(height=frame_height//font_height-1)
        self.console_size = Gui.CONSOLE_WIDTH * (frame_height//font_height-1)

    #
    def run(self):
        self.mainloop()


# Command line parameters..
prs = argparse.ArgumentParser()
prs.add_argument("--input","-i",metavar="input_file",default=None,type=str,help="ROM file to load")
prs.add_argument("--output","-o",metavar="output_file",default=None,type=str,help="ROM file to save instead of flashing")
prs.add_argument("--flash","-f",dest="flash_rom",default=False,action="store_true",help="Flash ROM file")
prs.add_argument("--patch_usa","-u",dest="patch_usa",action="store_true",default=False,help="Attempt patching USA region protection")
prs.add_argument("--jpn","-j",dest="make_jpn",action="store_true",default=False,help="Make USA ROM to Japan ROM (reverse bytes)")
prs.add_argument("--remove","-r",dest="remove_hdr",action="store_true",default=False,help="Remove possible ROM header")
prs.add_argument("--port","-p",metavar="usb_port",default=None,help="Force USB Serial port")
args = prs.parse_args()

if (__name__ == "__main__"):
    if (sys.argv.__len__() == 1):
        ui = Gui()

    else:
        ui = Con(
            args=args
        )

    #
    ui.output(f"PC Engine flash tool GUI v{Gui.VERSION_MAJOR}.{Gui.VERSION_MINOR}\n")
    ui.output(f"pce_flasher v{pce_flasher.VERSION_MAJOR}.{pce_flasher.VERSION_MINOR}\n")
    ui.output(f"(c) 2022 Jouni 'Mr.Spiv' Korhonen\n\n")

    ui.run()
