/*
 * This file contains diff processing regex patterns that
 * are used with filesChangedIn(), which is located in funcs.groovy.
 *
 * _inv lists contain inverse regex search patterns and others contain regular
 * regex search patterns.
 *
 * Please see the header for filesChangedIn() for a description on how to
 * use these regex patterns.
 *
 * These functions can be loaded into a variable in Jenkinsfile's by using the
 * load command.
 *
 * Example:
 *   patterns = load "${params.BASE_WORKSPACE}/scripts/jenkins-includes/patterns.groovy"
 */

// Jenkins test script directory
jjobs        = ["^scripts/jenkins-jobs.*"]
fishnet      = ["^fishnet.*"]
// Generic SDK Simulation
gen_sim_inv  = jjobs + fishnet
// common paths with platform abstraction that need to be excluded from basic inverse search
common_inv   = ["^driver.*", "^devices.*", "^sai.*"] + fishnet
// Pacific
pc           = ["^driver/pacific.*", "^driver/shared.*", "^devices/pacific.*"]
pc_inv       = common_inv + ["^npl/gibraltar.*"]
// Gibraltar
gb           = ["^driver/gibraltar.*", "^driver/shared.*", "devices/gibraltar.*"]
gb_inv       = common_inv + ["^npl/pacific.*"]
// Palladium
pl           = ["^driver/palladium.*", "^driver/shared.*", "^devices/akpg/palladium.*",
                    "^devices/akpg/common.*"]
pl_inv       = common_inv
// Graphene
gr           = ["^driver/graphene.*", "^driver/shared.*", "^devices/akpg/graphene.*",
                    "^devices/akpg/common.*"]
gr_inv       = common_inv
// Argon
ag           = ["^driver/argon.*", "^driver/shared.*", "^devices/akpg/argon.*",
                    "^devices/akpg/common.*"]
ag_inv       = common_inv
// LPM Feature
lpm          = ["^driver/shared/src/hw_tables/lpm.*", "^driver/shared/test/hw_tables/lpm.*",
                    "^driver/shared/include/hw_tables.*", "^driver/shared/src/common.*",
                    "^driver/shared/include/common.*"]
// Fishnet Simulations use the same logic as non-fishnet but do not ignore the fishnet directory
pc_fnet_inv  = pc_inv - fishnet
gb_fnet_inv  = gb_inv - fishnet
gr_fnet_inv  = gr_inv - fishnet

return this