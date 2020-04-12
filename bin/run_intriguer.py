#!/usr/bin/env python2
import argparse
import time
import os
import subprocess

ARCH32 = 32
ARCH64 = 64

def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('-i', dest='input_file', help='An input file', required=True)
    p.add_argument('-o', dest='output_dir', help='An output directory', required=True)
    p.add_argument('-t', dest='timeout', help='A timeout')
    p.add_argument('-s', dest='gen_testcases', help='Skip generating testcases')
    p.add_argument('cmd', nargs='+', help='cmd')
    return p.parse_args()

def execute(cmd) :
    fd = subprocess.Popen(cmd, shell=True,
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE)
    return fd.stdout, fd.stderr

def check_binary(target_bin):
    stdout, stderr = execute('objdump -a ' + target_bin) 

    arch = stdout.read()

    if arch.find('elf32') >= 0:
        return 32
    elif arch.find('elf64-x86-64') >= 0:
        return 64
    else:
        return -1

def generate_testcase(input_file, outdir):
    f = open(input_file, 'r')
    input_data = f.read()
    f.close()

    f = open(os.path.join(outdir, 'field.out'), 'r')

    fields = f.read().splitlines()

    f.close()

    i = 0

    for field in fields:
        f = field.split('\t')
        start = f[0]
        size = f[1]

        for field_token in f[2:]:
            field_marker = field_token[0]
            values = field_token[1:].split(',')

            for v in values:

                if v == '': continue

                output_data = input_data

                if v[0] == ':':
                    multi_values = v.split(':')[1:]

                    for mv in multi_values:
                        start_, size_, value_ = mv.split('_')

                        if start_ == 'x': start_ = start
                        if size_ == 'x': size_ = size

                        output_data = output_data[:int(start_)] + value_.decode('hex') + output_data[int(start_)+int(size_):]

                    fout = open(outdir + '/' + str(i) + '_' + field_marker + '_' + str(start) + '_' + str(size) + '_complex', 'w')
                    fout.write(output_data)
                    fout.close()

                else:
                    if len(v) % 2 == 1:
                        v = '0' + v

                    output_data = output_data[:int(start)] + v.decode('hex') + output_data[int(start)+int(size):]
                    
                    fout = open(outdir + '/' + str(i) + '_' + field_marker + '_' + str(start) + '_' + str(size), 'w')
                    fout.write(output_data)
                    fout.close()

                i += 1

    print('%d test cases are generated.' % i)

def main():
    args = parse_args()
    
    os.environ['ASAN_OPTIONS'] = 'detect_leaks=0'

    INTRIGUER_ROOT = os.environ['INTRIGUER_ROOT']
    PIN_ROOT = os.path.join(INTRIGUER_ROOT, 'third_party/pin-3.7-97619-0d0c92f4f')

    TARGET_ARCH = check_binary(args.cmd[0])

    if TARGET_ARCH == -1:
        return

    if os.path.exists(args.output_dir) == False:
        os.mkdir(args.output_dir)

    os.system('rm -r ' + args.output_dir + '/* 2>/dev/null')

    intriguer_start = time.time()
    start_time = time.time() 

    cmd = ''
    cmd += 'cat ' + args.input_file + ' | '

    if args.timeout != None:
        cmd += 'timeout -k 5 ' + str(int(args.timeout) * 20 / 90) + ' '

    cmd += os.path.join(PIN_ROOT, 'pin')
    cmd += ' -t '

    if TARGET_ARCH == ARCH64:
        cmd += os.path.join(INTRIGUER_ROOT, 'pintool/obj-intel64/executionMonitor.so')

    elif TARGET_ARCH == ARCH32:
        cmd += os.path.join(INTRIGUER_ROOT, 'pintool/obj-ia32/executionMonitor.so')

    cmd += ' -i ' + args.input_file
    cmd += ' -o ' + os.path.join(args.output_dir, 'trace.txt')
    cmd += ' -l ' + os.path.join(args.output_dir, 'taint.out')
    cmd += ' -- ' + ' '.join(args.cmd) + ' > /dev/null'

    cmd = cmd.replace('@@', args.input_file)

    print('[CMD]: ' + cmd)
    os.system(cmd)

    print('--- Execution Monitor takes %s seconds ---' %(time.time() - start_time))

    start_time = time.time() 

    cmd = ''

    if args.timeout != None:
        cmd += 'timeout -k 5 ' + str(int(args.timeout) * 70 / 90) + ' '

    cmd += os.path.join(INTRIGUER_ROOT, 'traceAnalyzer/traceAnalyzer') + ' '
    cmd += os.path.join(args.output_dir, 'trace.txt') + ' '
    cmd += args.input_file + ' '
    cmd += os.path.join(args.output_dir, 'field.out') + ' > '
    cmd += os.path.join(args.output_dir, 'field_log')

    print('[CMD]: ' + cmd)
    os.system(cmd)

    print('--- Trace Analyzer takes %s seconds ---' %(time.time() - start_time))

    if args.gen_testcases == None:
        generate_testcase(args.input_file, args.output_dir)

    f = open(os.path.join(args.output_dir, 'time'), 'w')
    f.write(str(float(time.time() - intriguer_start)))
    f.close()

if __name__ == '__main__':
    main()