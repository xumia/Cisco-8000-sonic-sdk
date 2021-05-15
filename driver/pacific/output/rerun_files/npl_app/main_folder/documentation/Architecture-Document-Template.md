# Feature Name
Overview of the feature

## Definitions

## Functional Requirements Summary

## Non Functional Requirements Summary

## Architecture
Overview of the Architecture

### NOS
A basic description of the information the NOS will generate to configure/operate the feature and how will it use the SDK API

### SDK
A basic description of what the SDK will do.
What information will it expect from NOS, and how it is translated to the API provided by P4
This part needs to be ironed out with the SDK.

### Dataplane
An architectural view of the feature with no P4 specific details like macro names, expected
The information the SDK need to configure. Tables, Keys, Payload fields, 
How is that information going to be used with respect to the hardware. What work is done at which processing stage.

## Scale
What are the limiting factors in terms of scale: number of counters, tunnels, ACE, ...
## Performance
What is the expected performance of the feature

## Limitations
Other limitations or conditions where the feature is disabled, contradicts other features ...

## Application Notes
Instructions to users on how to configure the feature, including non-NPU definitions - registers, TM.