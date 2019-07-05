#!/usr/bin/env python3.7
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

import sys, os, argparse
import zipfile
import tempfile
from struct import *

elements = {6:
  {
    0x12:"Region",
    0x43:"Root Type (info)",
    0x44:"rescue Version",
    0x4a:"16 byte string 0 terminated",
    0x4e:"Rom Version",
    0x58:"Alternate ROM Version?",
    0x5e:"OEMINFO_VENDER_AND_COUNTRY_NAME_COTA", #Taken from fastboot logs
    0x5b:"Hardware Version Customizeable",
    0x5c:"USB Switch?", # Guessed from fastboot logs
    0x61:"Hardware Version",
    0x62:"PRF?",
    0x65:"Rom Version Customizeable",
    0x67:"CN or CDMA info 0x67",
    0x68:"CN or CDMA info 0x68",
    0x6a:"CN or CDMA info 0x6a",
    0x6b:"CN or CDMA info 0x6b",
    0x6f:"Software Version",
    0x73:"Oeminfo Gamma", # From fastboot, but who knows what it actually is, has to do with hisifb_write_gm_to_reserved_mem and the display panel
    0x76:"pos_delivery constant",
    0x8b:"Unknown SHA256 1",
    0x85:"3rd_recovery constant",
    0x8c:"Software Version as CSV",
    0x8d:"Unknown SHA256 2",
    0x96:"Unknown SHA256 3",
    0xa6:"Update Token",
    0xa9:"Some kind of json changelog",
    0x15f:"Logo Boot", # Can be overriden in product, version, vendor or system partitions
    0x160:"Logo Battery Empty",
    0x161:"Logo Battery Charge",
  }, 8:
  {
    0x5c:"Userlock",
    0x5d:"System Lock State",
    0x28:"Version number",
    0x33:"Software Version as CSV",
    0x35:"semicolon separated text containing device identifiers, possibly used in bootloader code generation",
    0x3f:"update token",
    0x50:"cust version",
    0x52:"preload version",
    0x56:"system version",
    0x5ec:"build number",
    0x5ee:"model number",
    0xc:"system security data",
    0x1197:"Logo Battery Charge",
    0x1196:"Logo Battery Empty",
    0x1196:"Logo additional (custom format)",
    0x1195:"Logo Google",
  }
}
## Userlock definitions
# 01 means relocked (FRP is unlocked)
# 00 means relocked frp (FRP is locked)
# 03 unlocked frp (FRP is locked)
# 04 unlocked (FRP is unlocked)
# 05 unlocked debug (GUI-mode, buggy)
# 06 unlocked no-frp (FRP is not visible or active)

def element(version, key):
    returnvalue = elements.get(version, []).get(key, None)
    if (returnvalue == None):
        #returnvalue="0x%04x" % key
        returnvalue="" #hex(key)
    return returnvalue

def unzip(filename):
    tempdir=tempfile.gettempdir()
    zip_ref = zipfile.ZipFile(filename, 'r')
    zip_ref.extract("oeminfo",tempdir)
    zip_ref.close()
    return os.path.join(tempdir, "oeminfo")

def unpackOEM(f, outdir=None):
    # added feature for 2 iterations so we learn what oeminfo this is and act accordingly
    if (outdir == None):
        HW_Version=b"" #61
        HW_Region=b""  #12
        SW_Version=b""  #4e

    binary = f.read()
    content_length=len(binary)
    content_startbyte=0
    #catch wrong filesize - cheap but works for my needs
    if content_length != 67108864:
        print("Wrong filesize")
        #return
    #if we know the name already, do we have the out dir available?
    if outdir != None:
        if not os.path.exists(outdir):
            os.makedirs(outdir)

        #iterate the whole binary
    while content_startbyte <content_length:
        (header, version_number, id, type, data_len, age) = unpack("8sIIIII",binary[content_startbyte:content_startbyte+0x1c])
#        print("{:<10}||{:<10}||{:<10}||{:<10}||{:<10}||{:<10}".format(repr(header), repr(fixed6), repr(id), repr(type), repr(data_len), repr(age)))
        #Valid header?
        version = None
        if header == b"OEM_INFO":
            if version == None:
                version = version_number
            if version != version_number:
                print("version number changed during parsing! wtf")
                return
            if version_number == 8:
                pass
            if version_number == 6:
                pass
            #Catch special values for directory naming
            if id == 0x61:
                HW_Version = binary[content_startbyte+0x200:content_startbyte+0x200+data_len]
            if id == 0x12:
                HW_Region = binary[content_startbyte+0x200:content_startbyte+0x200+data_len]
            if id == 0x4e:
                SW_Version = binary[content_startbyte+0x200:content_startbyte+0x200+data_len]
            #prepare the "outfilename"
            if outdir != None:
                fileout = "{:x}-{:x}-{:x}-{:x}".format(id, type, age, content_startbyte)
                print("hdr:{:<8} age:{:3x} id:{:5x} {} ".format(header.decode('utf-8'), age, id, element(version, id)))
                with open(os.path.join(outdir, fileout+".bin"), "wb") as f:
                    f.write(binary[content_startbyte+0x200:content_startbyte+0x200+data_len])
                if element(version, id):
                    os.symlink(fileout+".bin", os.path.join(outdir, element(version, id)+"."+hex(content_startbyte)))
                if (version == 6 and type == 0x1fa5) or (version == 8 and (type == 0x2399 or type == 0x1fa5)):
                    if element(version, id):
                        os.symlink(fileout+".bin", os.path.join(outdir, element(version, id)+"."+hex(content_startbyte)+".bmp"))
        #forward another 0x400 bytes for upcoming "oem_info"
        content_startbyte+=0x400;
    #return directory name
    if outdir == None:
        outdir = HW_Version.decode('utf8')+"#"+HW_Region.decode('utf8').replace("/","-")+"#"+SW_Version.decode('utf8').split('\0', 1)[0]
        f.seek(0, 0)
        unpackOEM(f, outdir)
    return outdir

def encodeOEM(out_filename):
    out = bytearray(b'\x00'*0x4000000)
    counter=0
    content_startbytes = []
    for root, subFolder, files in os.walk("."):
        for item in files:
            if item.endswith(".bin"):
                id, type, age, content_startbyte = item.split(".")[0].split("-")
                buf_start = int(content_startbyte, 16)
                with open(os.path.join(root, item), "rb") as infile:
                    data=infile.read()
                    content_length=len(data)
                    if int(id, 16) == 0x69 or int(id, 16) == 0x57 or int(id, 16) == 0x44:
                        out[buf_start-0x1000:buf_start]=b'\xff'*0x1000 #The 0x1000 bytes before each entry should be 00'd out. However, the 0s should be applied before, NOT AFTER, the previous entry has applied its FF's for the 1k after
                    if int(type, 16) != 0x1fa5 or (int(id, 16) == 0x15f and int(age, 16) > 1) and (int(id, 16) != 0x160 and int(id, 16) != 161):
                        out[buf_start:buf_start+0x1000]=b'\xff'*0x1000
                    pack_into("8sIIIII",out,buf_start,b"OEM_INFO", 6, int(id,16), int(type,16), int(content_length), int(age,16))
                    out[buf_start+0x200:buf_start+0x200+content_length]=data
                #fileNamePath = str(os.path.join(str(root),str(subFolder),str(item)))
# Huawei decided to randomly put FFs in their file, I pay respects below.
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
    return ""

def replaceOEM(f, elements, out):
    binary = bytearray(f.read())
    content_length=len(binary)
    content_startbyte=0
    count = 0
    #catch wrong filesize - cheap but works for my needs
    if content_length != 67108864:
        print("Wrong filesize")
        return
    while content_startbyte <content_length:
        (header, fixed6, id, type, data_len, age) = unpack("8sIIIII",binary[content_startbyte:content_startbyte+0x1c])
        #Valid header?
        if header == b"OEM_INFO":
            if id in elements.keys():
                # All we care about is data_len.
                content_len = len(elements[id])
                pack_into("8sIIIII", binary, content_startbyte, b"OEM_INFO", 6, id, type, content_len, age)
                binary[content_startbyte+0x200:content_startbyte+0x200+content_len] = elements[id]
                count += 1
        content_startbyte+=0x400;
    out.write(bytes(binary))
    return count



def help(script):
    print(script+' -a <action> -i <inputfile> -r <replace_inputfile> -o <outputfile> -t <type 0x00>')
    sys.exit()


class StoreDictKeyPair(argparse.Action):
     def __init__(self, option_strings, dest, nargs=None, **kwargs):
         self._nargs = nargs
         super(StoreDictKeyPair, self).__init__(option_strings, dest, nargs=nargs, **kwargs)
     def __call__(self, parser, namespace, values, option_string=None):
         my_dict = {}
         for kv in values:
             k,v = kv.split("=")
             k = int(k, 0)
             if v[0] == "#":
                 with open(v, 'rb') as f:
                     v = f.read()
             else:
                 v = v.encode('utf-8')
             my_dict[k] = v
         if hasattr(namespace, self.dest) and getattr(namespace, self.dest) != None:
             my_dict = {**getattr(namespace, self.dest), **my_dict}
         setattr(namespace, self.dest, my_dict)


def main(argv):
    parser = argparse.ArgumentParser()
    subparsers = parser.add_subparsers(required=True)

    parser_extract = subparsers.add_parser("extract")
    parser_extract.add_argument("-i", "--input", dest='input', action='store', type=argparse.FileType('rb'), required=True)
    parser_extract.add_argument("-o", "--output", dest='output', action='store', type=str, default=None)
    parser_extract.set_defaults(func=unpackOEM)

    parser_pack = subparsers.add_parser("pack")
    parser_pack.add_argument("-i", "--input", dest='input', action='store', type=str, required=True)
    parser_pack.add_argument("-o", "--output", dest='output', action='store', type=argparse.FileType('wb'), required=True)
    parser_pack.set_defaults(func=encodeOEM)

    parser_replace = subparsers.add_parser("replace")
    parser_replace.add_argument("-i", "--input", dest='input', action='store', type=argparse.FileType('rb'), required=True)
    parser_replace.add_argument("-o", "--output", dest='output', action='store', type=argparse.FileType('wb'), required=True)
    parser_replace.add_argument("-e", "--elements", dest='elements', action=StoreDictKeyPair, nargs="+", required=True)
    parser_replace.set_defaults(func=replaceOEM)

    if len(sys.argv) < 2:
        sys.stderr.write('error: no subcommand\n')
        sys.stderr.flush()
        parser.print_help()
        sys.exit()
    args = parser.parse_args()

    if hasattr(args, 'elements'):
        print(args.func(args.input, args.elements, args.output))
    else:
        print(args.func(args.input, args.output))

#    in_filename=''
#    out_filename = ''
#    action = ''
#    type = '0x'
#    rin_filename=''

#    try:
#        opts, args = getopt.getopt(argv[1:],"ha:i:o:r:t:",["action=","ifile=","ofile=","type="])
#    except getopt.GetoptError:
#        help(argv[0])
#        sys.exit(2)
#    for opt, arg in opts:
#        if opt == '-h':
#            help(argv[0])

#        elif opt in ("-i", "--ifile"):
#            in_filename = arg
#        elif opt in ("-o", "--ofile"):
#            out_filename = arg
#        elif opt in ("-r", "--rfile"):
#            rin_filename = arg
#        elif opt in ("-t", "--type"):
#            type = arg
#        elif opt in ("-a", "--action"):
#            if (arg != "decode" and arg != "replace" and arg != "encode"):
#                print("wrong -a")
#            action = arg

    #validate if a file is given
#    if in_filename == "":
#        help(argv[0])

#    if os.path.splitext(in_filename)[1] == ".zip":
#            in_filename = unzip(in_filename)

#    if action == "" or action == "decode":
#        #:decode
#        outdir = unpackOEM(in_filename)
#        unpackOEM(in_filename,outdir)

#    if action == "replace":
#        if rin_filename == "" or out_filename == "" or type == '0x':
#            help(argv[0])
#        print("replace")
        #:replace
#        data_arr =  unpackOEM(in_filename,None,int(type,16))
#        #print data_arr
#        replaceOEM(in_filename,rin_filename,data_arr,out_filename)

#    if action == "encode":
#        if out_filename == "":
#            help(argv[0])
#        print("encode")
#        encodeOEM(out_filename)


if __name__ == "__main__":
   main(sys.argv)

