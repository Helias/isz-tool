#!/usr/bin/env python

# Copyright (C) 2012 Olivier Serres - Helias

#    This file is part of ISZ-tool.
#
#    ISZ-tool is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    ISZ-tool is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with ISZ-tool.  If not, see <http://www.gnu.org/licenses/>.

import wx
import argparse
import bz2
import ctypes
import os
import sys
import zlib

class ISZ_header(ctypes.LittleEndianStructure):
    _pack_ = 1
    _fields_ = [
        ("signature", ctypes.c_char * 4),
        ("header_size", ctypes.c_ubyte),
        ("version_number", ctypes.c_ubyte),
        ("volume_serial_number", ctypes.c_uint32),
        ("sector_size", ctypes.c_uint16),
        ("total_sectors", ctypes.c_uint),
        ("encryption_type", ctypes.c_ubyte),
        ("segment_size", ctypes.c_int64),
        ("nblock", ctypes.c_uint),
        ("block_size", ctypes.c_uint),
        ("pointer_length", ctypes.c_ubyte),
        ("file_seg_number", ctypes.c_byte),
        ("chunk_pointers_offset", ctypes.c_uint),
        ("segment_pointers_offset", ctypes.c_uint),
        ("data_offset", ctypes.c_uint),
        ("reserved", ctypes.c_ubyte),
        ("checksum1", ctypes.c_uint32),
        ("size1", ctypes.c_uint32),
        ("unknown2", ctypes.c_uint32),
        ("checksum2", ctypes.c_uint32)
    ]

    password_types = {
        0: 'No password',
        1: 'Password protected',
        2: 'Encrypted AES128',
        3: 'Encrypted AES192',
        4: 'Encrypted AES256'
    }

    def read_header(self, f):
        byte_read = f.readinto(self)

        if byte_read != 64:
            raise Exception('Error while reading the ISZ header only got (%d bytes)' % byte_read)

        if self.signature != b'IsZ!':
            raise Exception('Not an ISZ file (invalid signature)')

        if self.version_number != 1:
            raise Exception('ISZ version not supported')

    def get_uncompressed_size(self):
        return self.sector_size * self.total_sectors

    def print_isz_infos(self):
        print(self.get_isz_description())

class ISZ_sdt(ctypes.LittleEndianStructure):
    "Segment Definition Table (SDT)"

    _pack_ = 1
    _fields_ = [
        ("size", ctypes.c_int64),
        ("number_of_chunks", ctypes.c_int32),
        ("first_chunck_number", ctypes.c_int32),
        ("chunk_offset", ctypes.c_int32),
        ("left_size", ctypes.c_int32)
    ]

class StorageMethods:
    (Zeros, Data, Zlib, Bzip2) = range(4)

class ISZ_File():
    isz_header = ISZ_header()
    isz_segments = []
    chunk_pointers = []
    fp = None
    filename = None

    def close_file(self):
        if self.fp:
            self.fp.close()
            self.fp = None
        self.isz_segments = []
        self.chunk_pointers = []

    def xor_obfuscate(self, data):
        """Obfuscate or de-obfuscate data.
        
        Part of the isz files are obfuscated with a simple xor cipher)
        """

        code = (0xb6, 0x8c, 0xa5, 0xde)
        for i in range(len(data)):
            data[i] = data[i] ^ code[i%4]
        return data

    def read_chunk_pointers(self):
        """Read and decode the chunk pointer table.
        
        The ISO is divided into chunks and stored using different compression
        methods (0: bytes of zeros, 1: data, 2: zlib compressed, 3: bzip2
        compressed).
        """
        if self.isz_header.chunk_pointers_offset == 0:
            # if chunk_pointers_offset == 0, there is one uncompressed chunk
            tup = (1, self.isz_header.size1)
            self.chunk_pointers.append(tup)
            return

        if self.isz_header.pointer_length != 3:
            raise Exception('Only pointer sizes of 3 implemented')

        table_size = self.isz_header.pointer_length * self.isz_header.nblock
        self.fp.seek(self.isz_header.chunk_pointers_offset)
        data = bytearray(self.fp.read(table_size))
        data2 = self.xor_obfuscate(data)

        for i in range(self.isz_header.nblock):
            data = data2[i*3:(i+1)*3]
            val = data[2]*256*256 + data[1]*256 + data[0]
            data_type = val >> 22
            data_size = val & 0x3fffff
            tup = (data_type, data_size)
            self.chunk_pointers.append(tup)

    def print_chunk_pointers(self):
        comp_types = {0: 'Zeros', 1: 'Data', 2: 'Zlib', 3: 'BZIP2'}
        for (data_type, size) in self.chunk_pointers:
            s_type = comp_types[data_type]
            str_ptr = '%d %x %s ' % (size, size, s_type)
            print(str_ptr)

    def name_generator_1(self, seg_id):
        if seg_id != 0:
            return self.filename[:-4] + '.i%02d' % (seg_id)
        else:
            return self.filename

    def name_generator_2(self, seg_id):
        return self.filename[:-11] + '.part%02d.isz' % (seg_id + 1)

    def name_generator_3(self, seg_id):
        return self.filename[:-12] + '.part%03d.isz' % (seg_id + 1)

    def name_generator_no_change(self, seg_id):
        return self.filename

    def detect_file_naming_convention(self):
        """Find the naming convention for the ISZ segments."""

        if self.filename.endswith('.isz'):
            name_generators = [self.name_generator_1, self.name_generator_2,
                    self.name_generator_3]
            for ng in name_generators:
                if os.path.exists(ng(1)):
                    self.name_generator = ng
                    return
            raise Exception('Unable to find the naming convention used for the multi-part ISZ file')
        else:
            raise Exception('For multi-parts ISZ files, the first file need to have an .isz extension')

    def get_segment_name(self, seg_id):
        return self.name_generator(seg_id)

    def check_segment_names(self):
        """Verify the presence of all the ISZ files (segments)."""
        for i in range(len(self.isz_segments)):
            if not os.path.exists(self.get_segment_name(i)):
                raise Exception('Unable to find segment number %d' % (i))

    def read_segment(self):
        """Read a segment description from the ISZ file."""

        data = bytearray(self.fp.read(ctypes.sizeof(ISZ_sdt)))
        data = self.xor_obfuscate(data)
        seg = ISZ_sdt.from_buffer_copy(data)
        return seg

    def read_segments(self):
        """Read the segment table. Each segment correspond to an ISZ file."""
        if self.isz_header.segment_pointers_offset == 0:
            uniq_seg = ISZ_sdt()

            uniq_seg.size = 0
            uniq_seg.number_of_chunks = self.isz_header.nblock
            uniq_seg.first_chunck_number = 0
            uniq_seg.chunk_offset = self.isz_header.data_offset
            uniq_seg.left_size = 0

            self.isz_segments.append(uniq_seg)
        else:
            self.fp.seek(self.isz_header.segment_pointers_offset)
            seg = self.read_segment()
            while seg.size != 0:
                self.isz_segments.append(seg)
                seg = self.read_segment()

        if len(self.isz_segments) > 1:
            self.detect_file_naming_convention()
        else:
            self.name_generator = self.name_generator_no_change

        self.check_segment_names()

    def open_isz_file(self, filename):
        """Open and read the headers of an ISZ file."""
        self.close_file()
        self.filename = filename
        self.fp = open(filename, 'rb')

        self.isz_header.read_header(self.fp)

        if self.isz_header.file_seg_number != 0:
            raise Exception('Not the first segment in a set')

        self.read_segments()
        self.read_chunk_pointers()
        #self.print_chunk_pointers()

    def read_data(self, seg_id, offset, size):
        """Read a block of data from the specified segement."""

        fp = open(self.name_generator(seg_id), 'rb')
        fp.seek(offset)
        data = fp.read(size)
        fp.close()

        return data

    def get_block(self, block_id):
        """Locate and read block #block_id."""

        (block_type, block_size) = self.chunk_pointers[block_id]

        for seg_id in range(len(self.isz_segments)):
            segment = self.isz_segments[seg_id]
            first_block_id = segment.first_chunck_number
            last_block_id = segment.first_chunck_number + \
                    segment.number_of_chunks - 1

            if block_id >= first_block_id and block_id <= last_block_id:
                # We have the good segment
                cur_offset = segment.chunk_offset

                # find the correct offset
                for i in range(segment.first_chunck_number, block_id):
                    (block_type2, block_size2) = self.chunk_pointers[i]
                    if block_type2 != StorageMethods.Zeros:
                        cur_offset = cur_offset + block_size2

                size_to_read = block_size
                if block_id == last_block_id:
                    size_to_read = size_to_read - segment.left_size

                data = self.read_data(seg_id, cur_offset, size_to_read)

                # A block can be split between two segments
                if block_id == last_block_id and segment.left_size != 0:
                    data2 = self.read_data(seg_id + 1, 64, segment.left_size)
                    data = b"".join([data, data2])

                if len(data) != block_size:
                    raise Exception('Unable to read block %d' % (block_id))

                return data

        raise Exception('Unable to find the segment of block %d' % (block_id))

    def decompress_block(self, block_id):
        """Read and decompress block block_id."""

        (data_type, size) = self.chunk_pointers[block_id]

        if data_type == StorageMethods.Zeros:
            return bytes(size)

        data = self.get_block(block_id)

        if data_type == StorageMethods.Data:
            return data

        elif data_type == StorageMethods.Zlib:
            return zlib.decompress(data)

        elif data_type == StorageMethods.Bzip2:
            data = bytearray(data)
            data[0] = ord('B') #Restore a correct header...
            data[1] = ord('Z')
            data[2] = ord('h')
            return bz2.decompress(data)


    def extract_to(self, filename):
        """Extract the .iso to filename."""

        iso_fp = open(filename, 'wb')

        crc = 0
	dialog = wx.ProgressDialog('Converting to ISO', 'Conversion in progress...', len(self.chunk_pointers))
	dialog.Show()

        for block_id in range(len(self.chunk_pointers)):
	    dialog.Update(block_id)
            data = self.decompress_block(block_id)
            iso_fp.write(data)
            crc = zlib.crc32(data, crc) & 0xffffffff

        iso_fp.close()
	dialog.Destroy()

        crc = ~crc & 0xffffffff

        if crc != self.isz_header.checksum1:
            raise Exception('CRC Error during extraction')

class Frame(wx.Frame):
    def __init__(self, *args, **kwds):
        kwds["style"] = wx.DEFAULT_FRAME_STYLE
        wx.Frame.__init__(self, *args, **kwds)
	
        self.label_1 = wx.StaticText(self, -1, "ISZ Manager")
        self.ChooseFile = wx.Button(self, -1, "Choose Files...")
        self.control = wx.TextCtrl(self, -1, "")
        self.ConvertISO = wx.Button(self, -1, "Convert to ISO")

	#Menu
	self.menubar = wx.MenuBar()
        self.files = wx.Menu()
        self.Quit = wx.MenuItem(self.files, 1, "Exit\tCtrl+Q", "", wx.ITEM_NORMAL)
	self.Quit.SetBitmap(wx.Bitmap('icons/Exit.png'))
	self.files.AppendItem(self.Quit)
        self.menubar.Append(self.files, "File")
        self.about= wx.Menu()
        self.Info = wx.MenuItem(self.about, 2, "Info", "", wx.ITEM_NORMAL)
	self.Info.SetBitmap(wx.Bitmap('icons/Info.png'))
	self.about.AppendItem(self.Info)
        self.menubar.Append(self.about, "About")
        self.SetMenuBar(self.menubar)

        self.__set_properties()
        self.__do_layout()

        self.Bind(wx.EVT_BUTTON, self.OnOpen, self.ChooseFile)
	self.Bind(wx.EVT_BUTTON, self.ConvertToISO, self.ConvertISO)
	self.Bind(wx.EVT_MENU, self.OnExit, self.Quit)
	self.Bind(wx.EVT_MENU, self.OnInfo, self.Info)

    def __set_properties(self):
        self.SetTitle("ISZ Manager")
	_icon = wx.EmptyIcon()
	_icon.CopyFromBitmap(wx.Bitmap("icons/greentux.ico", wx.BITMAP_TYPE_ANY))
	self.SetIcon(_icon)
        self.label_1.SetBackgroundColour(wx.Colour(233, 255, 212))
        self.label_1.SetForegroundColour(wx.Colour(111, 111, 111))
        self.label_1.SetFont(wx.Font(20, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "Sans"))
        self.control.SetMinSize((400, 30))
        self.control.SetFont(wx.Font(10, wx.DEFAULT, wx.NORMAL, wx.NORMAL, 0, "Sans"))
        self.control.Enable(False)
	self.control.SetBackgroundColour(wx.Colour(255, 255, 255))

    def __do_layout(self):
        sizer_1 = wx.BoxSizer(wx.VERTICAL)
        sizer_1.Add(self.label_1, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 10)
        sizer_1.Add(self.ChooseFile, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 10)
        sizer_1.Add(self.control, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 10)
        sizer_1.Add(self.ConvertISO, 0, wx.ALL | wx.ALIGN_CENTER_HORIZONTAL, 10)
        self.SetSizer(sizer_1)
        sizer_1.Fit(self)
        self.Layout()
	self.Centre()
	
    def OnOpen(self,event):
	global dirname
	global filenameH
	dirname = ''
	dlg = wx.FileDialog(self, "Choose a file", dirname, "", "*.isz", wx.OPEN)
	if dlg.ShowModal() == wx.ID_OK:
		self.control.Clear()
		filenameH = dlg.GetFilename()
		dirname = dlg.GetDirectory()
		self.control.SetValue(dirname+"/"+filenameH)
		filenameH = filenameH.replace(".isz", "")
	dlg.Destroy()
	
    def ConvertToISO(self, event):
	isz = ISZ_File()
        src_isz = dirname+"/"+filenameH+".isz"
        dest_iso = dirname+"/"+filenameH+".iso"
        if not dest_iso:
            if src_isz.endswith('.isz'):
                dest_iso = src_isz[:-4] + '.iso'
            else:
                dest_iso = src_isz + '.iso'

	sys.stdout.flush()
	isz.open_isz_file(src_isz)
	isz.extract_to(dest_iso)
	isz.close_file()
	
    def OnInfo(self, event):
	wx.MessageBox('\n ISZ Manager was written in Python by Oserres and Helias and it is released under GNU GPL license \n', 'Info', wx.OK | wx.ICON_INFORMATION)

    def OnExit(self, event):
	self.Close()

if __name__ == "__main__":
    app = wx.PySimpleApp(0)
    wx.InitAllImageHandlers()
    ISZManager = Frame(None, -1, "")
    app.SetTopWindow(ISZManager)
    ISZManager.Show()
    app.MainLoop()
