import os, threading
import tkinter.filedialog

from tkinter import *
from traceback import format_exc
from array import array
from time import time, sleep
from struct import unpack

################################################
#
# This whole script is full of stylistic muck
# because it was written in 2015 when I was
# still a very VERY novice programmer.
#
# I just don't care enough or have enough
# time to spend cleaning it up and making
# it pretty. I spent a little time tweaking
# but it was mostly slight speedups and making
# the GUI work better on most operating systems
#
################################################


"""######################################"""
#      LZSS DECOMPRESSION CONSTANTS
"""######################################"""

BUF_FILL_CHAR = 0

LEN_BITS = 4
LEN_MASK = (2**LEN_BITS)-1
OFF_BITS = 12
OFF_MASK = (2**OFF_BITS-1)<<LEN_BITS

HEADER_LEN = 4
THRESHOLD = 3

BUFFER_START = LEN_MASK + THRESHOLD

DICT_SIZE = 2**OFF_BITS

DECOMP_BUFFER_SIZE = (THRESHOLD + LEN_MASK) * 8


#it's not known which key a quest uses until you try it
"""IF NEW KEYS ARE ADDED TO ZC IN THE FUTURE, THEY CAN BE ADDED TO THIS
LIST ALSO, IF ANYONE KNOWS HOW THE COMPRESSION WORKS ON THE OLDER QUESTS,
FEEL FREE TO ADD IT. THE DECRYPTION KEYS ARE ALREADY HERE"""
QUEST_DECRYPTION_KEYS = (
    0x4C358938,
    0x91B2A2D1,
    0x4A7C1B87,
    0xF93941E6,
    0xFD095E94)

QUEST_DECRYPTION_KEYS_A = (
    0x62E9,
    0x7D14,
    0x1A82,
    0x02BB,
    0xE09C)

QUEST_DECRYPTION_KEYS_B = (
    0x3619,
    0xA26B,
    0xF03C,
    0x7B12,
    0x4E8F)


#these are used to figure out if the quest is decrypting properly
OLD_QUEST_MATCH_STRING = bytearray(b'AG Zelda')
NEW_QUEST_MATCH_STRING = bytearray(b'AG ZC En')
SAVE_FILE_MATCH_STRING = bytearray(b'slh!')

SAVE_FILE_HEADER_STRING = bytearray(b'Zelda Classic Save File')


class E_Zunder_Window(Tk):
    XOR_Key = list(bytearray(b'longtan'))

    No_Pass_Hash = b'\xd4\x1d\x8c\xd9\x8f\x00\xb2\x04\xe9\x80\x09\x98\xec\xf8\x42\x7e'

    Curr_Dir = os.path.abspath(os.curdir)

    prev_progress = -1

    def __init__(self, **options):
        Tk.__init__(self, **options )

        self.title("Eternal Zunder: Zelda Classic 1.92+ Quest Deprotector V2.2")
        self.geometry("450x100+0+0")
        self.resizable(0, 0)

        self.Input_Path = StringVar(self)
        self.curr_ui_state = -1
        self.next_ui_state = 0

        self.Processing = False
        self.Begin_Decryption = False

        self.Current_Job_Min = 0
        self.Current_Job_Max = 100
        self.Current_Progress = 0

        self.Idle_Update_Interval = 100

        #Create the input box
        self.Input_File_Field = Entry(self, textvariable=self.Input_Path)
        self.Input_File_Field.config(width=63, state=DISABLED)

        #Add the buttons
        self.btn_browse = Button(self, text="Browse...", width=10, command=self._Make_Browse)
        self.btn_deprotect = Button(self, text="Deprotect", width=10, command=self._Start_Deprotection)

        #Create and start the deprotect thread
        self.Deprotect_Thread = threading.Thread(target=self._Deprotect_Quest)
        self.Deprotect_Thread.daemon = True
        self.Deprotect_Thread.start()

        self.Displayed_Info_Text_Box = Text(self, height=3, bg='#ece9d8', state=NORMAL, width=68)

        self.Input_File_Field.grid(row=0, column=0, columnspan=5, sticky="news")
        self.btn_browse.grid(row=0, column=6, columnspan=1)
        self.btn_deprotect.grid(row=1, column=6, columnspan=1)

        self.Displayed_Info_Text_Box.grid(row=1, column=0, sticky="news", rowspan=2, columnspan=5)

        self.update()
        w, h = self.winfo_reqwidth(), self.winfo_reqheight()
        self.geometry("%sx%s" % (w, h))
        self.minsize(width=w, height=h)

        self._Idle_Update()

    def _Start_Deprotection(self):
        if not self.Processing:
            self.next_ui_state = 0
            self.Begin_Decryption = True

    #This function is to make the window to browse for the tags folder
    def _Make_Browse(self):
        if not self.Processing:
            temp = filedialog.askopenfilename(initialdir=self.Curr_Dir, title='Select the protected file')
            if len(temp):
                self.Input_File_Field.config(state=NORMAL)
                self.Input_File_Field.delete(0,END)
                self.Input_File_Field.insert(0,temp)
                self.Input_File_Field.config(state=DISABLED)
                self.Curr_Dir = os.path.dirname(temp)
                self.next_ui_state = 0

    def _Idle_Update(self):
        progress = self.prev_progress
        if self.Processing:
            progress = (self.Current_Progress - self.Current_Job_Min) / max(1, self.Current_Job_Max)

        if self.curr_ui_state == self.next_ui_state and progress == self.prev_progress:
            self.after(self.Idle_Update_Interval, self._Idle_Update)
            return

        self.curr_ui_state = self.next_ui_state
        self.Displayed_Info_Text_Box.config(state=NORMAL)
        self.Displayed_Info_Text_Box.delete('0.0', END)
        self.prev_progress = progress

        if self.next_ui_state == 0:
            text = ('This program will deprotect any Zelda Classic quest\n'
                    'made in version 1.92 and higher, including v2.5.')
        elif self.next_ui_state == 1:
            text = 'Reading quest from file...\t%d%%' % int(100 *progress)
        elif self.next_ui_state == 2:
            text = 'First decryption pass...\t%d%%' % int(100 *progress)
        elif self.next_ui_state == 3:
            text = 'Second decryption pass...\t%d%%' % int(100 *progress)
        elif self.next_ui_state == 4:
            text = 'Decompressing...\t%d%%' % int(100 *progress)
        elif self.next_ui_state == 5:
            text = 'Finished!\nQuest password has been removed!'
        elif self.next_ui_state == 6:
            text = 'Finished!\nSave file has been decrypted and uncompresssed!'
        elif self.next_ui_state == -1:
            text = 'Could not locate the file specified.'
        elif self.next_ui_state == -2:
            text = ('Something went wrong with the password removal.\n'
                    'Error report has been printed to the console.')
        elif self.next_ui_state == -3:
            text = 'Could not locate matching keyset to decrypt quest.'
        elif self.next_ui_state == -4:
            text = ('Quest is too old. I don\'t know how the compression\n'
                    'works on a quest this old, thus I cant unpack it.')

            
        self.Displayed_Info_Text_Box.insert(INSERT, text)

        self.Displayed_Info_Text_Box.config(state=DISABLED)
        self.update_idletasks()
        self.after(self.Idle_Update_Interval, self._Idle_Update)

    def _Deprotect_Quest(self):
        """
           This function will load the file at the current
           input path, decrypt it, decompress it, remove
           the password, and write it to a new file.
        """
        while True:
            sleep(0.5)

            if self.Processing or not self.Begin_Decryption:
                continue

            self.Processing = True
            self.Begin_Decryption = False

            #get the input file path and make the slashes uniform
            Input_Path = self.Input_Path.get().replace('/', '\\')
            Output_Path = os.path.splitext((os.path.dirname(os.path.realpath(Input_Path)) + "\\" +
                                            os.path.basename(Input_Path) ))[0] + ".qsu"

            if not os.path.isfile(Input_Path):
                self.next_ui_state = -1
                self.Processing = False
                continue

            self.next_ui_state = 1
            try:
                '''OPEN THE ENCRYPTED FILE AND TURN IT INTO A MUTABLE ARRAY'''
                with open(Input_Path, 'r+b') as in_file:
                    in_bytes = in_file.read()

                key_set, new_format, is_save_file = self._Get_Key_Set_and_Is_New_Format(in_bytes)

                if key_set < 0:
                    self.next_ui_state = -3
                elif not new_format:
                    self.next_ui_state = -4
                else:
                    self.next_ui_state = 2
                    '''remove the outer layer of encryption'''
                    in_bytes = self._Main_Decrypt(in_bytes, key_set)

                    if is_save_file:
                        Output_Path = os.path.splitext(Output_Path)[0] + ".unc.sav"
                    else:
                        self.next_ui_state = 3
                        '''remove the inner layer of encryption'''
                        self._XOR_Decrypt(in_bytes)


                    if not os.path.exists(os.path.dirname(Output_Path)):
                        os.makedirs(os.path.dirname(Output_Path))


                    '''OPEN THE OUTPUT FILE'''
                    with open(Output_Path, 'w+b') as out_file:
                        self.next_ui_state = 4
                        '''decompress the file so it can be modified'''
                        self._LZSS_Decompress(in_bytes, out_file)

                        if not(is_save_file):
                            """Replace the password hash with a "no-password" password hash"""
                            self._Remove_Password(out_file)
                            self.next_ui_state = 5
                        else:
                            self.next_ui_state = 6
            except:
                self.next_ui_state = -2
                print(format_exc())

            self.Processing = False

    def _Main_Decrypt(self, in_bytes, key_set):
        if in_bytes[:23] == SAVE_FILE_HEADER_STRING:
            Header_String_Len = 23
        else:
            Header_String_Len = 24

        #try to undo the outermost layer of encryption
        self.Current_Progress = 0
        self.Current_Job_Max = len(in_bytes)-(Header_String_Len+8)

        #array that will contain the decrypted bytes
        #we trim the header and footer hash off
        out_bytes = bytearray(in_bytes[Header_String_Len+4: -4])


        #create the quest key and XOR it with the internal key
        Decrypt_Key = unpack(">I", in_bytes[Header_String_Len:Header_String_Len+4])[0]
        Decrypt_Key ^= QUEST_DECRYPTION_KEYS[key_set]

        Key_Piece_A = QUEST_DECRYPTION_KEYS_A[key_set]
        Key_Piece_B = QUEST_DECRYPTION_KEYS_B[key_set]

        Key_Temp_1 = Key_Temp_2 = 0
        Final_Block_Key = 0

        try:
            #loop over the bytes in sets of 2 at a time
            for i in range(0, len(out_bytes), 2):
                Key_Temp_1 =  Decrypt_Key      + Key_Piece_A
                Key_Temp_2 = (Decrypt_Key>>16) + Key_Piece_B

                #if Temp_A will be negative
                if Decrypt_Key & 0x800000:
                    Key_Temp_1 += 0xFFffFFff

                    #if the Decrypt_Key is negative, set EDX
                    if Decrypt_Key & 0x80000000:
                        Key_Temp_2 += 0xFFfeFFfd
                    else:
                        Key_Temp_2 += 0xFFffFFff + ((Decrypt_Key>>7) & 0xFFfe)
                else:
                    Key_Temp_1 += Decrypt_Key<<9

                    #if the Decrypt_Key is negative, set EDX
                    if Decrypt_Key & 0x80000000:
                        Key_Temp_2 += 0xFFfeFFfe
                    else:
                        Key_Temp_2 += (Decrypt_Key>>7) & 0xFFfe

                Key_Temp_1 &= 0xFFff
                Key_Temp_2 &= 0xFFff


                # if Temp_B is negative
                Decrypt_Key = (Key_Temp_2<<16) | Key_Temp_1
                if Key_Temp_1 & 0x8000:
                    Decrypt_Key = (Decrypt_Key + 0xFFff0000) & 0xFFffFFff

                Final_Block_Key = (Key_Temp_1<<16) | Key_Temp_2


                # decrypt and write the bytes
                out_bytes[i]   = (out_bytes[i]^Final_Block_Key) & 0xFF
                out_bytes[i+1] = ((0x100000000 + out_bytes[i+1]) - Final_Block_Key) & 0xFF

                self.Current_Progress = i
        except IndexError:
            #it's quicker to just catch the exception here
            pass
        except:
            print(format_exc())

        self.Current_Progress = len(in_bytes)-(Header_String_Len+8)
        return out_bytes

    def _Get_Key_Set_and_Is_New_Format(self, in_bytes):
        for key_set in range(len(QUEST_DECRYPTION_KEYS)):
            test_bytes = self._Main_Decrypt(in_bytes[:50], key_set)

            if test_bytes[5:13] in (OLD_QUEST_MATCH_STRING, NEW_QUEST_MATCH_STRING):
                if test_bytes[3] >= 116:
                    return(key_set, True, False)
                else:
                    return(key_set, False, False)

            elif test_bytes[0:4] == SAVE_FILE_MATCH_STRING:
                return(key_set, True, True)

            else:
                self._XOR_Decrypt(test_bytes)

                if test_bytes[5:13] in (OLD_QUEST_MATCH_STRING, NEW_QUEST_MATCH_STRING):
                    if test_bytes[3] >= 116:
                        return(key_set, True, False)
                    else:
                        return(key_set, False, False)


        return (-1, False, False)

    def _XOR_Decrypt(self, in_bytes):
        self.Current_Job_Max = 6
        self.Current_Progress = 0

        #for i in range( len(in_bytes) ):
        #    #XOR the data with the key
        #    in_bytes[i] ^= self.XOR_Key[i%7]
        #    self.Current_Progress = i

        # this is a much faster version of the above code
        for i in range(7):
            # create a pre-XOR'd value mapping that can be used in a map call
            xor_map_function = bytearray(map(
                (lambda x: x ^ self.XOR_Key[i]),
                range(256)
                )).__getitem__

            in_bytes[i::7] = bytearray(map(xor_map_function, in_bytes[i::7]))

            self.Current_Progress = i

    def _LZSS_Decompress(self, in_bytes, out_file):
        i = HEADER_LEN  # current offset in the compressed data
        end_i = len(in_bytes)

        #array to hold the dictionary bytes
        dict_bytes = [BUF_FILL_CHAR]*DICT_SIZE
        dict_read_i  = 0
        dict_write_i = 0

        # make a temp buffer big enough to hold all
        # data decompressed from one set of flags
        temp_buffer = bytearray(DECOMP_BUFFER_SIZE)

        self.Current_Progress = i
        self.Current_Job_Max = end_i
        try:
            while i < end_i:
                flags = in_bytes[i]
                i += 1

                temp_i = 0
                # each bit in the flags determines how to copy the data
                for bit in range(8):
                    if (flags >> bit) & 1:
                        # if the flag is set then copy the byte directly from the input
                        temp_buffer[temp_i] = dict_bytes[dict_write_i] = in_bytes[i]

                        i += 1
                        temp_i += 1
                        dict_write_i = (dict_write_i + 1) % DICT_SIZE
                    else:
                        # if not, then copy a stream of bytes from the dictionary buffer
                        count = (in_bytes[i + 1] & LEN_MASK) + THRESHOLD
                        dict_read_i = (
                            in_bytes[i] + BUFFER_START +
                            ((in_bytes[i + 1] & OFF_MASK) << LEN_BITS)
                            ) % DICT_SIZE

                        i += 2
                        while count:
                            temp_buffer[temp_i] = dict_bytes[dict_write_i] = dict_bytes[dict_read_i]

                            temp_i += 1
                            count  -= 1
                            dict_read_i  = (dict_read_i  + 1) % DICT_SIZE
                            dict_write_i = (dict_write_i + 1) % DICT_SIZE

                out_file.write(temp_buffer[: temp_i])
                self.Current_Progress = i
        except IndexError:
            # IndexError being raised after we've parsed every input
            # byte is something we can expect. only print an exception
            # if not every byte has been read
            if i < len(in_bytes):
                print(format_exc())
            

    def _Remove_Password(self, out_file):
        out_file.seek(46)
        out_file.write(self.No_Pass_Hash)

    def Close(self):
        self.withdraw()


if __name__ == "__main__":
    Main_Window = E_Zunder_Window()
    Main_Window.mainloop()
