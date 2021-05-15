
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15



#ifndef __NPL_TABLES_COMPILER_GENERATED_CONFIG_H__
#define __NPL_TABLES_COMPILER_GENERATED_CONFIG_H__

#include "npl_tables_compiler_generated_config_types.h"
#include "nplapi/npl_table_types.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one {
    
    class npl_tables_compiler_generated_config {
        
    public:
        
        static table_compiler_generated_config_t get_table_config(npl_tables_e table_name, npl_context_e context);
        
        static ternary_table_compiler_generated_config_t get_ternary_table_config(npl_tables_e table_name, npl_context_e context);
        
        static table_compiler_generated_config_t get_lpm_table_config(npl_tables_e table_name);
        
    };
}

#endif
