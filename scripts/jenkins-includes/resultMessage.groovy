/*
 * This file contains the common status messages used to update GitHub Pull
 * Requests and Revisions by our Jenkinsfile's. These messages can
 * be loaded into a variable in Jenkinsfile's by using the load command.
 *
 * Example:
 *  resultMessage = load "${params.BASE_WORKSPACE}/scripts/jenkins-includes/resultMessage.groovy"
 */

def interface message {
    String SUCCESS = "Passed"
    String FAILURE = "Failed"
    String PENDING = "Pending"
    String SKIPPED = "Skipped"
    String PREV_SUCCESS = "Previously passed"
    String UNSTABLE = "Failure treated as Unstable"
    String DEFAULT = "default-message-unknown"
}

return message