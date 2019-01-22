#OEMINFO tool
#rysmario 2016
#   hackish tool to "unpack" a oeminfo from huawei
#
# I take NO responsibility for a brick, soft brick, alien abduction or anything

# takes arguments "decode", "encode", "replace"
#   decode is optional
#decode oeminfo.bin to folder created from oemeinfo content [i.e. VIE-AL10#all-cn#VIE-C00B176- Rayglobe ]
#   python oeminfo_decode_v2.py [decode] <oeminfo.bin>
#
#replace folder to out_file:
#   python oeminfo_decode_v2.py replae <existing_out_file> <replacement-file>

# Originally from https://forum.xda-developers.com/p9-plus/how-to/mod-oeminfo-structure-t3446382
# Came with no license, but in the OP is noted that you can do what you want, so I will relicense under GPLv3

# oeminfo unpacker for huawei
#   Some code from this file is copyright (C) 2019 Hackintosh5
#   Thanks to rysmario 2016, no copyright asserted by them.
#
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <https://www.gnu.org/licenses/>.

import sys, os, getopt
import zipfile
import tempfile
from struct import *

elements = {
    0x12:"Region",
    0x44:"rescue Version",
    0x4a:"16 byte string 0 terminated",
    0x4e:"Rom Version",
    0x58:"Alternate ROM Version?",
    0x5e:"OEMINFO_VENDER_AND_COUNTRY_NAME_COTA", #Taken from fastboot logs
    0x5b:"Hardware Version Customizeable",
    0x61:"Hardware Version",
    0x62:"PRF?",
    0x65:"Rom Version Customizeable",
    0x67:"CN or CDMA info 0x67",
    0x68:"CN or CDMA info 0x68",
    0x6a:"CN or CDMA info 0x6a",
    0x6b:"CN or CDMA info 0x6b",
    0x6f:"Software Version",
    0x76:"pos_delivery constant",
    0x8b:"Unknown SHA256 1",
    0x85:"3rd_recovery constant",
    0x8c:"Software Version as CSV",
    0x8d:"Unknown SHA256 2",
    0x96:"Unknown SHA256 3",
    0xa6:"Update Token",
    0xa9:"Some kind of json changelog",
    0x15f:"Logo Boot",
    0x160:"Logo Battery Empty",
    0x161:"Logo Battery Charge",
}
def element(key):
    returnvalue = elements.get(key)
    if (returnvalue == None):
        #returnvalue="0x%04x" % key
        returnvalue="" #hex(key)
    return returnvalue

def unzip(filename):
    tempdir=tempfile.gettempdir()
    zip_ref = zipfile.ZipFile(filename, 'r')
    #zip_ref.printdir()
    zip_ref.extract("oeminfo",tempdir)
    zip_ref.close()
    return os.path.join(tempdir, "oeminfo")

def unpackOEM(filename, outdir = None):
    # added feature for 2 iterations so we learn what oeminfo this is and act accordingly
    if (outdir == None):
        HW_Version=b"" #61
        HW_Region=b""  #12
        SW_Version=b""  #4e

    with open(filename, "rb") as f:
        binary = f.read()
        content_length=len(binary)
        content_startbyte=0

        #catch wrong filesize - cheap but works for my needs
        if content_length != 67108864:
            return

        #if we know the name already, do we have the out dir available?
        if outdir != None:
            if not os.path.exists(outdir):
                os.makedirs(outdir)

        #iterate the whole binary
        while content_startbyte <content_length:
            (header, fixed6, id, type, data_len, age) = unpack("8sIIIII",binary[content_startbyte:content_startbyte+0x1c])
#            print(header, fixed6, id, type, data_len, age)
            #Valid header?
            if header == b"OEM_INFO":
                #Catch special values for directory naming
                if id == 0x61:
                    HW_Version = binary[content_startbyte+0x200:content_startbyte+0x200+data_len]
                if id == 0x12:
                    HW_Region = binary[content_startbyte+0x200:content_startbyte+0x200+data_len]
                if id == 0x4e:
                    SW_Version = binary[content_startbyte+0x200:content_startbyte+0x200+data_len]

                #prepare the "outfilename"
#                fileout= "%s\\%04x-%04x-%04x" % (outdir, id,type, age)


                #write
                if outdir != None:
                    fileout = "{:x}-{:x}-{:x}-{:x}".format(id, type, age, content_startbyte)
                    print("hdr:%s age:%08x id:%04x %s " % (header.decode('utf-8'), age, id, element(id) ))
                    with open(os.path.join(outdir, fileout+".bin"), "wb") as f:
                        f.write(binary[content_startbyte+0x200:content_startbyte+0x200+data_len])
                    if element(id):
                        os.symlink(fileout+".bin", os.path.join(outdir, element(id)+"."+hex(content_startbyte)))
                    #print "%s" % (binary[content_startbyte+0x200:content_startbyte+0x200+data_len])
                    if type == 0x1fa5:
                        if element(id):
                            os.symlink(fileout+".bin", os.path.join(outdir, element(id)+"."+hex(content_startbyte)+".bmp"))
            #forward another 0x400 bytes for upcoming "oem_info"
            content_startbyte+=0x400;
    #return directory name
    if outdir == None:
        return HW_Version.decode('utf8')+"#"+HW_Region.decode('utf8').replace("/","-")+"#"+SW_Version.decode('utf8').split('\0', 1)[0]


def encodeOEM(out_filename):
    out = bytearray(b'\x00'*0x4000000)
    counter=0
    content_startbytes = []
    for root, subFolder, files in os.walk("."):
        for item in files:
            if item.endswith(".bin"):
                id, type, age, content_startbyte = item.split(".")[0].split("-")
                buf_start = int(content_startbyte, 16)
                print(item)
                with open(os.path.join(root, item), "rb") as infile:
                    data=infile.read()
                    content_length=len(data)
                    if int(id, 16) == 0x69 or int(id, 16) == 0x57 or int(id, 16) == 0x44:
                        out[buf_start-0x1000:buf_start]=b'\xff'*0x1000 #The 0x1000 bytes before each entry should be 00'd out. However, the 0s should be applied before, NOT AFTEr, the previous entry has applied its FF's for the 1k after
                    if int(type, 16) != 0x1fa5 or (int(id, 16) == 0x15f and int(age, 16) > 1) and (int(id, 16) != 0x160 and int(id, 16) != 161):
                        print(type)
                        out[buf_start:buf_start+0x1000]=b'\xff'*0x1000
                    pack_into("8sIIIII",out,buf_start,b"OEM_INFO", 6, int(id,16), int(type,16), int(content_length), int(age,16))
                    out[buf_start+0x200:buf_start+0x200+content_length]=data
                #fileNamePath = str(os.path.join(str(root),str(subFolder),str(item)))
#    out[0x55000:0x56000] = b'\xff'*0x1000
    out[0x5d000:0x5e000] = b'\xff'*0x1000
#    out[0x67000:0x68000] = b'\xff'*0x1000
    out[0x74000:0x75000] = b'\xff'*0x1000
#    out[0x2042000:0x2043000] = b'\xff'*0x1000
    out[0x204d000:0x204e000] = b'\xff'*0x1000
    out[0x2055000:0x2057000] = b'\xff'*0x2000
    out[0x205a000:0x205b000] = b'\xff'*0x1000
    out[0x205c000:0x205e000] = b'\xff'*0x2000
    out[0x2074000:0x2075000] = b'\xff'*0x1000
    out[0x28a4a50:0x2cb0000] = b'\xff'*0x40b5b0
#    out[0x2067000:0x2068000] = b'\xff'*0x1000
    with open(out_filename, "wb") as f:
        f.write(out)

def replaceOEM(in_filename,elements,out_filename):
    with open(filename, "rb") as f:
        binary = bytearray(f.read())
        content_length=len(binary)
        content_startbyte=0

        #catch wrong filesize - cheap but works for my needs
        if content_length != 67108864:
            return
        while content_startbyte <content_length:
            (header, fixed6, id, type, data_len, age) = unpack("8sIIIII",binary[content_startbyte:content_startbyte+0x1c])
#            print(header, fixed6, id, type, data_len, age)
            #Valid header?
            if header == b"OEM_INFO":
                if id in elements:
                    # All we care about is data_len.
                    content_length = len(elements[id])
                    pack_into("8sIIIII", binary, content_startbyte, b"OEM_INFO", 6, id, type, content_length, age)
                    binary[content_startbyte+0x200:content_startbyte+0x200+content_length] = elements[id]
            content_startbyte+=0x400;
        with open(out_filename, "wb") as out:
            out.write(bytes(binary))




def help(script):
    print(script+' -a <action> -i <inputfile> -r <replace_inputfile> -o <outputfile> -t <type 0x00>')
    sys.exit()

def main(argv):
    in_filename=''
    out_filename = ''
    action = ''
    type = '0x'
    rin_filename=''

    try:
        opts, args = getopt.getopt(argv[1:],"ha:i:o:r:t:",["action=","ifile=","ofile=","type="])
    except getopt.GetoptError:
        help(argv[0])
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            help(argv[0])

        elif opt in ("-i", "--ifile"):
            in_filename = arg
        elif opt in ("-o", "--ofile"):
            out_filename = arg
        elif opt in ("-r", "--rfile"):
            rin_filename = arg
        elif opt in ("-t", "--type"):
            type = arg
        elif opt in ("-a", "--action"):
            if (arg != "decode" and arg != "replace" and arg != "encode"):
                print("wrong -a")
            action = arg

    #validate if a file is given
#    if in_filename == "":
#        help(argv[0])

    if os.path.splitext(in_filename)[1] == ".zip":
            in_filename = unzip(in_filename)

    if action == "" or action == "decode":
        #:decode
        outdir = unpackOEM(in_filename)
        unpackOEM(in_filename,outdir)

    if action == "replace":
        if rin_filename == "" or out_filename == "" or type == '0x':
            help(argv[0])
        print("replace")
        #:replace
        data_arr =  unpackOEM(in_filename,None,int(type,16))
        #print data_arr
        replaceOEM(in_filename,rin_filename,data_arr,out_filename)

    if action == "encode":
        if out_filename == "":
            help(argv[0])
        print("encode")
        encodeOEM(out_filename)


if __name__ == "__main__":
   main(sys.argv)

