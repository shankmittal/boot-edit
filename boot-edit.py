import os
import sys
import struct
import mmap
import tempfile

from ctypes import *
from optparse import OptionParser

UINT8_SIZE = 1
UINT32_SIZE = 4

BOOT_MAGIC = "ANDROID!"
BOOT_MAGIC_SIZE = 8
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024

global header
global header_buf
global kernel_offset
global kernel_size
global ramdisk_offset
global ramdisk_size
global rest_offset
global rest_size

class Header(Structure):
    _fields_ = [('magic', c_char * BOOT_MAGIC_SIZE),
                ('kernel_size', c_uint),
                ('kernel_addr', c_uint),
                ('ramdisk_size', c_uint),
                ('ramdisk_addr', c_uint),
                ('second_size', c_uint),
                ('second_addr', c_uint),
                ('tags_addr', c_uint),
                ('page_size', c_uint),
                ('unused', c_uint*2),
                ('name', c_char * BOOT_NAME_SIZE),
                ('cmdline', c_char * BOOT_ARGS_SIZE),
                ('id', c_uint*8),
                ('extra_cmdline', c_char * BOOT_EXTRA_ARGS_SIZE)]

def dump_hex(num):
    return hex(num).rsplit('L')[0]

def openfile(name, perm):
    try:
        f = open(name, perm)
    except:
        print("could not open path {0}".format(name))
        print("Do you have read permissions on the path?")
        sys.exit(1)
    return f

def copy_file(src_file, des_file, size, block_size):
    count = 0
    while count != size:
        des_file.write(src_file.read(block_size))
        count += block_size

def file_size(f):
    old_file_pos = f.tell()
    f.seek(0, os.SEEK_END)
    size = f.tell()
    f.seek(old_file_pos, os.SEEK_SET)
    return size

def pad(des_file, pad_size):
    if pad_size == 0:
            return
    des_file.write('\0' * pad_size)

def round_of_page(size, page_size):
    return int((size + page_size - 1) / page_size) * page_size

def read_header(bootimg):
    global header_buf
    global header
    bootimg.seek(0)
    buf = bootimg.read(2048)
    header = cast(buf, POINTER(Header)).contents
    bootimg.seek(0);
    header_buf = bootimg.read(header.page_size)
    header = cast(header_buf, POINTER(Header)).contents

def boot_stats(bootimg):
    global kernel_offset
    global kernel_size
    global ramdisk_offset
    global ramdisk_size
    global rest_offset
    global rest_size

    read_header(bootimg)

    if header.magic != BOOT_MAGIC:
            print('Not a valid boot image. Exitting...')
            sys.exit(1)

    #calculate file size:
    bootimg.seek(0, os.SEEK_END)
    total_size = bootimg.tell()

    kernel_size = round_of_page(header.kernel_size, header.page_size)
    ramdisk_size = round_of_page(header.ramdisk_size, header.page_size)
    rest_size = (total_size - header.page_size - kernel_size - ramdisk_size)

    kernel_offset = header.page_size
    ramdisk_offset = kernel_offset + kernel_size
    rest_offset = ramdisk_offset + ramdisk_size

def process_cmdline(cmdline):
    if cmdline[:1] == '+':
            return header.cmdline + ' ' + cmdline[1:]
    else:
            return cmdline

def split(bootimg, name):
    # make dir
    if not os.path.exists(name):
        print ('!!! Out directory does not exist. Creating...')
        try:
            os.makedirs(name)
        except:
            print ("Failed to create %s. You probably don't have permissions there. Bailing." % name)
            sys.exit(1)

    # write kernel image
    bootimg.seek(kernel_offset);
    buf = bootimg.read(header.kernel_size);
    kernel = openfile(name+'/kernel', 'wb');
    kernel.write(buf)
    kernel.close()

    # write ramdisk image
    bootimg.seek(ramdisk_offset);
    buf = bootimg.read(header.ramdisk_size);
    ramdisk = openfile(name+'/ramdisk.img', 'wb');
    ramdisk.write(buf)
    ramdisk.close()

    # write rest image
    bootimg.seek(rest_offset);
    buf = bootimg.read(rest_size);
    rest = openfile(name+'/rest.img', 'wb');
    rest.write(buf)
    rest.close()

    # write boot info
    buf_info = "cmdline: %s\npage_size: %d\nkernel_addr: 0x%x\nramdisk_addr:0x%x\n" \
            % (header.cmdline, header.page_size, header.kernel_addr, header.ramdisk_addr)
    boot_info = openfile(name+'/boot_info', 'wb')
    boot_info.write(buf_info)
    boot_info.close()

def replace(bootimg, options):
    if options.ramdiskimg is None and \
       options.kernel is None and \
       options.cmdline is None:
            print "Nothing to do for replace"
            return

    # split in tmp location
    tmp_path = tempfile.gettempdir()
    split(bootimg, tmp_path)

    # create copy
    new_bootimg = openfile(options.newfile, 'wb')

    if options.cmdline is not None:
            header.cmdline = process_cmdline(options.cmdline)

    if options.ramdiskimg is not None:
            ramdisk_path = options.ramdiskimg
    else:
            ramdisk_path = tmp_path + '/ramdisk.img'

    if options.kernel is not None:
            kernel_path = options.kernel
    else:
            kernel_path = tmp_path + '/kernel'

    rest_path = tmp_path + '/rest.img'

    # open files to confirm that we can access them
    kernel = openfile(kernel_path, 'rb')
    ramdisk = openfile(ramdisk_path, 'rb')
    rest = openfile(rest_path, 'rb')

    # fix kernel and ramdisk sizes in header
    header.kernel_size = file_size(kernel)
    header.ramdisk_size = file_size(ramdisk)
    rest_size = file_size(rest)

    #copy header
    buf = header_buf
    new_bootimg.write(buf)

    #copy kenel
    buf = kernel.read(header.kernel_size)
    new_bootimg.write(buf)
    # add padding
    pad_size = round_of_page(header.kernel_size, header.page_size)-header.kernel_size
    pad(new_bootimg, pad_size)
    kernel.close()

    #copy ramdisk
    buf = ramdisk.read(header.ramdisk_size)
    new_bootimg.write(buf)
    # add padding
    pad_size = round_of_page(header.ramdisk_size, header.page_size) - header.ramdisk_size
    pad(new_bootimg, pad_size)
    ramdisk.close()

    #copy rest
    buf = rest.read(rest_size)
    new_bootimg.write(buf)
    rest.close()

    new_bootimg.truncate()
    print('new boot image: %s' % options.newfile)
    print('new cmdline: %s' % header.cmdline)

    new_bootimg.close()

if __name__ == '__main__':
    usage = 'usage: %prog [options to print]. Run with --help for more details'
    parser = OptionParser(usage)
    parser.add_option('-b', '--boot-image', dest='bootimg',
                      help='Boot Image Path')
    parser.add_option('-s', '--split', action='store_true',
                      help='Split boot image')
    parser.add_option('-o', '--overwrite', action='store_true',
                      help='overwrite current boot image')
    parser.add_option('-k', '--kernel', dest='kernel',
                      help='Replace kernel image')
    parser.add_option('-r', '--ramdisk', dest='ramdiskimg',
                      help='Replace ramdisk image')
    parser.add_option('-c', '--cmdline', dest='cmdline',
                      help='Replace kernel command line')
    parser.add_option('-n', '--newfile-path', dest='newfile',
                      help='New boot image path')
    (options, args) = parser.parse_args()

    args = ''
    for arg in sys.argv:
        args = args + arg + ' '

    if options.bootimg is None:
        print("No boot image file given! Exiting...")
        parser.print_usage()
        sys.exit(1)

    bootimg = openfile(options.bootimg, 'rb')
    boot_stats(bootimg)

    print ('cmdline: %s' % header.cmdline)

    if options.overwrite and options.newfile is not None:
        print("Both -o and -n options are not allowed together")
        parser.print_usage()
        sys.exit(1)

    if options.overwrite:
        options.newfile = options.bootimg
    else:
        if options.newfile is None:
            options.newfile = 'updated-boot.img'

    if options.split:
        name = os.path.basename(options.bootimg)
        name = name.replace('.img','')
        split(bootimg, name)

    if options.cmdline is not None or \
       options.kernel is not None or \
       options.ramdiskimg is not None:
        replace(bootimg, options)
