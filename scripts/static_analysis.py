#!/usr/bin/env python

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

def actual_permissions(vmx) :
    result = {}
    perms_access = vmx.get_tainted_packages().get_permissions( [] )
    for perm in perms_access :
        result[perm] = len(perms_access[ perm ])
    return result

def native_method_count(vm) :
    count = 0
    for i in vm.get_methods() :
        if i.get_access_flags() & 0x100 :
            ++count
    return count

def main(options, args) :
    print options.input
    print options.output
    if options.input == None or options.output == None :
        print "static_analysis.py -i <inputfile> -o <outputfolder>"
        sys.exit(2)
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
                        #'files'              : a.get_files_types(),
                        'libraries'          : a.get_libraries(),
                        'isCryptoCode'       : analysis.is_crypto_code(vmx),
                        'isDynamicCode'      : analysis.is_dyn_code(vmx),
                        'isNativeCode'       : analysis.is_native_code(vmx),
                        'nativeMethodCount'  : native_method_count(vm),
                        'isReflectionCode'   : analysis.is_reflection_code(vmx),
                        'reflectionCount'    : len(vmx.get_tainted_packages().search_methods("Ljava/lang/reflect/Method;", ".", ".")),
                        'isAsciiObfuscation' : analysis.is_ascii_obfuscation(vm),
                        'permissions'        : a.get_permissions(),
                        'permDetails'        : a.get_details_permissions(),
                        'actualPermissions'  : actual_permissions(vmx),
                    }

                    with io.open(options.output + "/" + hashfile(options.input) + ".json", 'w', encoding='utf-8') as f:
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

