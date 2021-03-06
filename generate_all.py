#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import socket
import common

path = os.getcwd()
bindings = []

for d in os.listdir(path):
    if os.path.isdir(d):
        if not d in ('configs', '.git', '__pycache__'):
            bindings.append(d)
            sys.path.append(os.path.join(path, d))

bindings = sorted(bindings)

# bindings
for binding in bindings:
    if binding in ('tcpip', 'modbus'):
        continue

    module = __import__('generate_{0}_bindings'.format(binding))
    print("\nGenerating bindings for {0}:".format(binding))
    module.generate(os.path.join(path, binding))

# doc
for binding in bindings:
    module = __import__('generate_{0}_doc'.format(binding))
    for lang in ['en', 'de']:
        print("\nGenerating '{0}' documentation for {1}:".format(lang, binding))
        module.generate(os.path.join(path, binding), lang)

# zip
def run_zip_generator(path, binding):
    module = __import__('generate_{0}_zip'.format(binding))
    print("\nGenerating ZIP for {0}:".format(binding))
    module.generate(os.path.join(path, binding))

if socket.gethostname() == 'tinkerforge.com':
    run_zip_generator(path, 'javascript')
else:
    for binding in bindings:
        if binding in ('tcpip', 'modbus'):
            continue

        run_zip_generator(path, binding)

print('')
print('>>> Done <<<')
