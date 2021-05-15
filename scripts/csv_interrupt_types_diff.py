import argparse
import json
import yaml
import logging
import sys
import os
import csv
import re

def skip_record(record) -> bool:
    if record['interrupt_type'].lower() in ['summary', 'mem_protect'] or record['is_masked'].lower() == 'true' or record['block'].lower() == 'sbif' or re.search(r'serdes_pool', record['block']):
        return True
    return False

def patch_alias_dict(alias_dict):
    #alias_dict['counters.bank_6k[]'] = 'counters_bank_group'
    #alias_dict['slice_pair[].idb.res'] = 'idb_res'
    pass

def load_alias_dict(filenames):
    ret = {}
    for filename in filenames:
        json_list = None
        with open(filename, 'r') as file:
            json_list = json.loads(re.sub(r'\[\d+\]', r'[]', re.sub(r'(\\\w)|(gibraltar_tree\.)|(pacific_tree\.)', r'', file.read())).lower())
        for item in json_list:
            ret[item['lbr_block_name']] = item['lbr_block_name']
            if item['sw_path'] in ret and item['lbr_block_name'] != ret[item['sw_path']]:
                logging.warning('Overwriting key {} with value {}, old value {}'.format(item['sw_path'], item['lbr_block_name'], ret[item['sw_path']]))
            ret[item['sw_path']] = item['lbr_block_name']

    patch_alias_dict(ret)
    return ret

def main(csv_sdk_filename, csv_external_filename, json_filenames, compare_sw_action_flag, log_file_name):
    logger = logging.getLogger('root').getChild('main')
    alias_dict = load_alias_dict(json_filenames)

    with open(csv_sdk_filename, 'r', encoding='utf-8-sig') as csv_sdk_file, open(csv_external_filename, 'r', encoding='utf-8-sig') as csv_external_file:
        csv_sdk = csv.reader(csv_sdk_file)
        csv_external = csv.reader(csv_external_file)
        columns_sdk = next(csv_sdk)
        columns_external = next(csv_external)
        rows_sdk = [dict(zip(columns_sdk, [x.lower() for x in line])) for line in csv_sdk if any(line)]
        rows_external_raw = [dict(zip(columns_external, [x.lower() for x in line])) for line in csv_external if any(line)]
        rows_external = []
        reg_current = None
        for row_raw in rows_external_raw:
            if row_raw['Reg/Field'] == 'register':
                reg_current = row_raw['Name']
            else:
                assert reg_current is not None, "Must be defined."
                rows_external.append(row_raw)
                row_raw['Register'] = reg_current

        line_to_lines = []
        for line_sdk in rows_sdk:
            if skip_record(line_sdk):
                continue
            block_name = line_sdk['block']
            register_name = line_sdk['register']
            bit_name = line_sdk['bit']
            block_alias_name = alias_dict[block_name]
            lines_external = find_lines(rows_external, alias_dict, block_name, register_name, bit_name)
            if len(lines_external) == 0:
                logger.warning('No pair found for block "{}", register "{}", bit "{}"'.format(block_name, register_name, bit_name))
            else:
                line_to_lines.append({'block_name' : block_name, 'register' : register_name, 'bit' : bit_name, 'type' : line_sdk['interrupt_type'], 'sw_action' : simplify_sw_action(line_sdk['app SW action']), 'pairs' : [{ 'block_name' : line_external['Block name'], 'register' : line_external['Register'], 'type' : line_external['Interrupt Type'], 'name' : line_external['Name'], 'sw_action' : simplify_sw_action(line_external['SW Action']) } for line_external in lines_external]})
        
        with open('file.json', 'w') as file:
            json.dump(line_to_lines, file, indent=4)
        with open('file.yaml', 'w') as file:
            yaml.dump(line_to_lines, file, sort_keys=False)
        
        logger.info('Number of registers with found pairs: {}'.format(len(line_to_lines)))
        output_json = {}
        compare_interrupt_types(line_to_lines, output_json)
        logger.debug(''.join(['_' for x in range (100)]))
        if compare_sw_action_flag:
            compare_sw_actions(line_to_lines, output_json)
        '''
        json_file_name = re.sub(r'(.*)\.\w+', r'\1_json.json', log_file_name)
        with open(json_file_name, 'w') as f:
            json.dump(output_json, f, indent=4)
        '''

def find_lines(external_csv_rows, alias_dict, sdk_block_name, sdk_register_name, sdk_bit_name):
    #found = [item for item in external_csv_rows if alias_dict.get(item['Block name'], 'unknown') == alias_dict[sdk_block_name] and item['Reg/Field'] == 'field' and any(list(filter(lambda x: camel_snake_to_canonical(x) == camel_snake_to_canonical(item['Name']), sdk_register_name)))]
    found = [item for item in external_csv_rows if alias_dict.get(item['Block name'], 'unknown') == alias_dict[sdk_block_name] and item['Reg/Field'] == 'field' and camel_snake_to_canonical(item['Name']) == camel_snake_to_canonical(sdk_bit_name) and camel_snake_to_canonical(item['Register']) == camel_snake_to_canonical(sdk_register_name)]
    return found

def camel_snake_to_canonical(name):
    #return re.sub(r'(\[\d+\.\.\d+\])', r'', re.sub(r'_', r'', name)).lower()
    return re.sub(r'(\[.*\])|_', r'', name).lower()

# interrupt types as defined in interrupt_types.h + some other types that appear in CSVs
def interrupt_type_to_num(interrupt_type):
    return {
        'mem_protect' : 0,
        'mem protect' : 0,
        'memprotect' : 0,
        'ecc_1b' : 1,
        'ecc 1b' : 1,
        'ecc1b' : 1,
        'ecc_2b' : 2,
        'ecc 2b' : 2,
        'ecc2b' : 2,
        'mac_link_down' : 3,
        'mac link down' : 3,
        'maclinkdown' : 3,
        'link_down' : 4,
        'link down' : 4,
        'linkdown' : 4,
        'misconfiguration' : 5,
        'mac_link_error' : 6,
        'mac link error' : 6,
        'maclinkerror' : 6,
        'link_error' : 7,
        'link error' : 7,
        'linkerror' : 7,
        'lack_of_resources' : 8,
        'lack of resources' : 8,
        'lackofresources' : 8,
        'threshold_crossed' : 9,
        'threshold crossed' : 9,
        'thresholdcrossed' : 9,
        'other' : 5,
        'summary' : 11,
        'interrupt_summary' : 11,
        'interrupt summary' : 11,
        'interruptsummary' : 11,
        'informative' : 5,
        'design_bug' : 13,
        'design bug' : 13,
        'designbug' : 13,
        'no_err_notification' : 14,
        'no err notification' : 14,
        'noerrnotification' : 14,
        'no err - notification' : 14,
        'no_err_internal' : 15,
        'no err internal' : 15,
        'noerrinternal' : 15,
        'counter_threshold_crossed' : 16,
        'counter threshold crossed' : 16,
        'counterthresholdcrossed' : 16,
        'credit_dev_unreachable' : 17,
        'credit dev unreachable' : 17,
        'creditdevunreachable' : 17,
        'lpm_sram_ecc_1b' : 18,
        'lpm sram ecc 1b' : 18,
        'lpmsramecc1b' : 18,
        'lpm_sram_ecc_2b' : 19,
        'lpm sram ecc 2b' : 19,
        'lpmsramecc2b' : 19,
        'queue_aged_out' : 20,
        'queue aged out' : 20,
        'queueagedout' : 20,
        'dram_corrupted_buffer' : 21,
        'dram corrupted buffer' : 21,
        'dramcorruptedbuffer' : 21,
        # other interrupt types which appear in CSV but not in interrupt_types.h:
        'debug' : 5,
        'ecc_error' : 22,
        'ecc error' : 22,
        'eccerror' : 22,
        'link_noise' : 24,
        'link noise' : 24,
        'linknoise' : 24,
        'oversubscription error' : 25,
        'data path error' : 26,
        'remote ecc error' : 27,

    }[interrupt_type.lower()]

def compare_interrupt_types(sdk_to_external_pairing, output_json):
    output_json['interrupt_types'] = []
    logger = logging.getLogger('root').getChild('compare_interrupt_types')
    type_pairs_count = {}
    mismatches = 0
    for item in sdk_to_external_pairing:
        sdk_interrupt_type = item['type']
        if len(item['pairs']) > 1:
            logger.info('Register has more than one pair, resolve manually: \n{}\n'.format(json.dumps(item, indent=4)))
            continue
        external_interrupt_type = item['pairs'][0]['type']
        if interrupt_type_to_num(sdk_interrupt_type) != interrupt_type_to_num(external_interrupt_type):
            to_sort = [sdk_interrupt_type, external_interrupt_type]
            to_sort.sort()
            tup = tuple(to_sort)
            if tup not in type_pairs_count:
                type_pairs_count[tup] = 1
            else:
                type_pairs_count[tup] += 1
            logger.error('Interrupt types differ: \n{}\n'.format(json.dumps(item, indent=4)))
            mismatches += 1
            output_json['interrupt_types'].append(item)

    type_pairs_count = ['{}<->{} : {}'.format(*k,type_pairs_count[k]) for k in type_pairs_count]
    logger.info('Individual interrupt missmatches count:\n{}\n'.format(json.dumps(type_pairs_count, indent=4)))
    logger.info('Number of interrupt mismatches: {}'.format(mismatches))
    
def simplify_sw_action(sw_action : str):
    if re.search(r'(SW_ACTION_NONE)|(SW ACTION NONE)', sw_action, re.IGNORECASE):
        return 'none'
    elif re.search(r'(SW_ACTION_HARD_RESET)|(SW ACTION HARD RESET)|(DEVICE HARD RESET)', sw_action, re.IGNORECASE):
        return 'hard_reset'
    elif re.search(r'(SW_ACTION_SOFT_RESET)|(SW ACTION SOFT RESET)|(DEVICE SOFT RESET)', sw_action, re.IGNORECASE):
        return 'soft_reset'
    elif re.search(r'(SW_ACTION_REPLACE_DEVICE)|(SW ACTION REPLACE DEVICE)', sw_action, re.IGNORECASE):
        return 'replace_device'
    else:
        return sw_action.lower()

def compare_sw_actions(sdk_to_external_pairing, output_json):
    with open('sdk_to_external_pairing.json', 'w') as f:
        f.write(json.dumps(sdk_to_external_pairing, indent=4))
    output_json['sw_actions'] = []
    logger = logging.getLogger('root').getChild('commpare_sw_actions')
    type_pairs_count = {}
    mismatches = 0
    for item in sdk_to_external_pairing:
        sdk_sw_action = item['sw_action']
        if len(item['pairs']) > 1:
            logger.info('Register has more than one pair, resolve manually: \n{}\n'.format(json.dumps(item, indent=4)))
            continue
        external_sw_action = item['pairs'][0]['sw_action']
        permitted_sw_actions = ['none', 'soft_reset', 'hard_reset', 'replace_device']
        #if sdk_sw_action != external_sw_action and sdk_sw_action in permitted_sw_actions and external_sw_action in permitted_sw_actions:
        if sdk_sw_action != external_sw_action:
            to_sort = [sdk_sw_action, external_sw_action]
            to_sort.sort()
            tup = tuple(to_sort)
            if tup not in type_pairs_count:
                type_pairs_count[tup] = 1
            else:
                type_pairs_count[tup] += 1
            logger.error('SW action differs: \n{}\n'.format(json.dumps(item, indent=4)))
            mismatches += 1
            output_json['sw_actions'].append(item)

    type_pairs_count = ['{}<->{} : {}'.format(*k,type_pairs_count[k]) for k in type_pairs_count]
    logger.info('Individual SW action missmatches count:\n{}\n'.format(json.dumps(type_pairs_count, indent=4)))
    logger.info('Number of SW action mismatches: {}'.format(mismatches))

# python3 csv_interrupt_types_diff.py -csv_external external.csv -csv_sdk gibraltar_interrupt_tree.csv -json block_to_sw_path_pacific.json -json block_to_sw_path_gibraltar.json -log_file file.log -sw_action
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-json', action='append', dest='json_filenames',default=[])
    parser.add_argument('-csv_sdk', action='store', dest='csv_sdk')
    parser.add_argument('-csv_external', action='store', dest='csv_external')
    parser.add_argument('-log_file', action='store', dest='log_file')
    parser.add_argument('-sw_action', action='store_true', dest='sw_action')
    results = parser.parse_args()

    file_handler = logging.FileHandler(filename=results.log_file)
    stdout_handler = logging.StreamHandler(sys.stdout)
    handlers = [file_handler, stdout_handler]
    logging.basicConfig(handlers=handlers, level=logging.DEBUG)
    logging.debug('CSV files: {}, {}'.format(results.csv_sdk, results.csv_external))
    logging.debug('JSON files: {}'.format([item for item in results.json_filenames]))

    main(results.csv_sdk, results.csv_external, results.json_filenames, results.sw_action, results.log_file)