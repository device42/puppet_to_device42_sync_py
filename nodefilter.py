# -*- coding: utf-8 -*-

# import re


def node_filter(ndata, filterlist):
    retval = True

    for flt in filterlist:
        if 'attribute' not in flt or 'value' not in flt:
            continue  # wrong structure
        apath = flt['attribute'].strip().split('.')
        fval = flt['value']
        oprt = flt['compare'].lower()  # operator
        inv = flt.get('invert', False)
        aroot = ndata
        # getting real value from attribute
        for akey in apath:
            if not isinstance(aroot, dict) or akey not in aroot:
                print("Attribute %s does not match: path not found" % flt['attribute'])
                # retval = retval and False
                return False
            aroot = aroot[akey]
        # Here 'aroot' should contain target attribute

        wrong_op = False
        if isinstance(aroot, basestring):
            if oprt in ['iequal', 'ieq']:
                retval = str(fval).lower() == aroot.lower()
            elif oprt in ['equal', 'eq']:
                retval = str(fval) == aroot
            elif oprt in ['igreater', 'igt']:
                retval = str(fval).lower() <= aroot.lower()
            elif oprt in ['greater', 'gt']:
                retval = str(fval) <= aroot
            elif oprt in ['iless', 'ilt']:
                retval = str(fval).lower() >= aroot.lower()
            elif oprt in ['less', 'lt']:
                retval = str(fval) >= aroot
            elif optr in ['isubstr', 'icontains']:
                retval = aroot.lower().find(str(fval).lower()) >= 0
            elif optr in ['substr', 'contains']:
                retval = aroot.find(str(fval)) >= 0
            elif optr in ['in', 'iin']:
                if isinstance(fval, (list, dict)):
                    if optr == 'in':
                        retval = aroot in fval
                    else:  # iin - case-insensitive 'in'
                        retval = any([True for v in fval if aroot.lower() == v.lower()])
                else:
                    print("Attribute %s: value of type %s does not support operator 'in', clause ignored" %
                          (flt['attribute'], type(fval)))
                    continue
            else:
                wrong_op = True

        elif isinstance(aroot, (list, dict)):
            if optr in ['has', 'contains']:
                retval = str(fval) in aroot
            elif optr in ['ihas', 'icontains']:
                retval = any([True for v in aroot if fval.lower() == v.lower()])
            elif optr in ['empty']:
                retval = not aroot
            else:
                wrong_op = True

        elif isinstance(aroot, (int, float, long)):
            if oprt in ['equal', 'eq']:
                retval = fval == aroot
            elif oprt in ['greater', 'gt']:
                retval = fval <= aroot
            elif oprt in ['less', 'lt']:
                retval = fval >= aroot
            else:
                wrong_op = True

        elif isinstance(aroot, (bool)):
            retval = aroot == fval

        else:
            print("Not supported attribute type: %s" % (type(aroot)))
            return False

        if wrong_op:
            print("Unknown operator '%s' for attribute '%s' of type %s, ignore clause" %
                  (oprt, flt['attribute'], type(aroot)))
            # return False
            continue

        if inv:
            retval = not retval

        if not retval:
            # print("Attribute '%s' does not match" % flt['attribute'])
            return False

    return retval
