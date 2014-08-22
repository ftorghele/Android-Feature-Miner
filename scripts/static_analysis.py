#!/usr/bin/env python
#
# ----------------------------------------------------------------------------------
# This file is part of {@link https://github.com/AndroSOM/FeatureMiner AndroSOM}.
#
# Copyright (c) 2014 AndroSOM
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
# ----------------------------------------------------------------------------------

import sys, io, os, json, hashlib

from optparse import OptionParser

sys.path.append("./tools/androguard")
from androguard.core import androconf
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.core.analysis import risk

def hashfile(filepath):
    sha1 = hashlib.sha1()
    f = open(filepath, 'rb')
    try:
        sha1.update(f.read())
    finally:
        f.close()
    return sha1.hexdigest()

def native_method_count(vm) :
    count = 0
    for i in vm.get_methods() :
        if i.get_access_flags() & 0x100 :
            ++count
    return count

def get_methods(cm, paths, result) :
    for path in paths :
        src_class_name, src_method_name, src_descriptor =  path.get_src( cm )
        dst_class_name, dst_method_name, dst_descriptor =  path.get_dst( cm )

        callerNamespace = src_class_name.split('/')
        del callerNamespace[-1]
        callerNamespace = "/".join(callerNamespace)

        if callerNamespace not in result:
            result[callerNamespace] = {}
        if dst_class_name not in result[callerNamespace]:
            result[callerNamespace][dst_class_name] = {}
        if dst_method_name not in result[callerNamespace][dst_class_name]:
            result[callerNamespace][dst_class_name][dst_method_name] = {}
        if dst_descriptor not in result[callerNamespace][dst_class_name][dst_method_name]:
            result[callerNamespace][dst_class_name][dst_method_name][dst_descriptor] = 1
        else :
            result[callerNamespace][dst_class_name][dst_method_name][dst_descriptor] += 1
    return result

def actual_permissions(vm, vmx) :
    # Get methods using permission
    result = {}
    perms_access = vmx.get_tainted_packages().get_permissions( [] )
    for perm in perms_access :
        if perm not in result:
            result[perm] = {}
        get_methods(vm.get_class_manager(), perms_access[ perm ], result[perm])
    return result

def main(options, args) :
    print options.input
    if options.input == None or options.output == None :
        print "static_analysis.py -i <inputfile> -o <outputfolder>"
        sys.exit(2)
    elif os.path.isfile(options.output + "/" + hashfile(options.input) + "_static.json") :
        print "\tstatic analysis found.. skipping.."
    else :
        ret_type = androconf.is_android( options.input ) 

        if ret_type == "APK" :
            try :
                a = apk.APK(options.input, zipmodule=2)
                if a.is_valid_APK() :

                    vm = dvm.DalvikVMFormat(a.get_dex())
                    vmx = analysis.uVMAnalysis(vm)

                    data = {
                        'mainActivity'       : a.get_main_activity(),
                        'activities'         : a.get_activities(),
                        'providers'          : a.get_providers(),
                        'receivers'          : a.get_receivers(),
                        'services'           : a.get_services(),
                        'androidVersion'     : a.get_androidversion_code(),
                        'maxSdkVersion'      : a.get_max_sdk_version(),
                        'minSdkVersion'      : a.get_min_sdk_version(),
                        'targetSdkVersion'   : a.get_target_sdk_version(),
                        'package'            : a.get_package(),
                        'libraries'          : a.get_libraries(),
                        'isCryptoCode'       : analysis.is_crypto_code(vmx),
                        'isDynamicCode'      : analysis.is_dyn_code(vmx),
                        'isNativeCode'       : analysis.is_native_code(vmx),
                        'nativeMethodCount'  : native_method_count(vm),
                        'isReflectionCode'   : analysis.is_reflection_code(vmx),
                        'reflectionCount'    : len(vmx.get_tainted_packages().search_methods("Ljava/lang/reflect/Method;", ".", ".")),
                        'isAsciiObfuscation' : analysis.is_ascii_obfuscation(vm),
                        'permissions'        : a.get_permissions(),
                        'actualPermissions'  : actual_permissions(vm, vmx),
                        'internalMethodCalls' : get_methods(vm.get_class_manager(), vmx.get_tainted_packages().get_internal_packages(), {}),
                        'externalMethodCalls' : get_methods(vm.get_class_manager(), vmx.get_tainted_packages().get_external_packages(), {})
                    }

                    with io.open(options.output + "/" + hashfile(options.input) + "_static.json", 'w', encoding='utf-8') as f:
                        f.write(unicode(json.dumps(data, sort_keys=False, indent=2, separators=(',', ': '), ensure_ascii=False)))

                else :
                    print "INVALID APK"
            except Exception, e :
                print "ERROR", e
                import traceback
                traceback.print_exc()

if __name__ == "__main__" :
    parser = OptionParser()
    parser.add_option("-i", "--input", dest="input", help="path to the APK file which shoud be analysed.")
    parser.add_option("-o", "--output", dest="output", help="folder to write the analysis result as json.")
    (options, args) = parser.parse_args()

    sys.argv[:] = args
    main(options, args)
