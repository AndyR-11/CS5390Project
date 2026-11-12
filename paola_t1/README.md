# T1: Message-Type Clustering

## Purpose

I built this module to group similar network messages before analyzing the fields
inside them. This is the T1 step of the project. The next step, T2, looks for the
boundaries between fields within each group.

For example, reading a sensor and writing a new value may produce different byte
patterns. My code looks for those patterns without being told where the protocol's
function code is located. A group number does not automatically tell us what a
message means. I check that separately when evaluating the results.

This is an initial clustering method, not a complete attack detector.

## How it works

The input is a list of records. Each record contains the message bytes in `raw`.

1. I group the training messages by their length.
2. Within each length, I examine the values at each byte position.
3. I select positions that have a small number of different values and low entropy.
   Here, low entropy means that a few values account for most observations.
4. I combine the bytes at those positions into a signature. Messages with the same
   length and signature belong to the same group.
5. I use the learned signatures to assign groups to new messages. A result of `-1`
   means that the signature or length is new, or had too few training examples.

The default settings allow 2 to 16 different values at a selected position, an
entropy of at most 1.5 bits, and at least 8 training examples for each length and
signature. These are starting values, not settings that will work best for every
capture.

The clustering algorithm uses only the raw bytes. It does not use attack labels,
timestamps, ports, or predefined Modbus field positions. The capture loader uses
the configured server port to select traffic before clustering.

## Files

| File | Purpose |
|---|---|
| `clustering.py` | Learns message patterns and assigns groups. |
| `run_t1.py` | Reads a capture, runs clustering, and saves a JSON result. |
| `test_clustering.py` | Tests the clustering code. |
| `validate.py` | Runs additional Modbus experiments and the existing detector evaluation. |
| `requirements.txt` | Lists the dependency needed to read captures. |
| `__init__.py` | Makes this folder a Python package. |
| `results/` | Stores saved experiment results, when included. |

## Running the code

I tested the code with Python 3.12. Keep the files inside the `paola_t1` folder and
run these commands from the repository's main folder, which contains `paola_t1`
and `modbus_ids`.

Install the capture-reading dependency:

```bash
python -m pip install -r paola_t1/requirements.txt
```

Run the tests:

```bash
python -m unittest paola_t1.test_clustering -v
```

Run T1 on the included normal Modbus capture:

```bash
python -m paola_t1.run_t1 modbus_ids/normal_traffic.pcapng --port 502 --out paola_t1/results/modbus_t1.json
```

The program learns from the first 70% of the capture in time order and tests on
the remaining 30%. The output includes the selected byte positions, group
signatures, packet assignments, and the fraction of unknown messages.

Use the port recorded in the capture. The example capture uses port 502, while
the lab scripts may use port 5020. For an OPC UA capture, provide its file path
and the appropriate port, such as 4840.

To apply the same trained model to another capture, add `--test-pcap`:

```bash
python -m paola_t1.run_t1 modbus_ids/normal_traffic.pcapng --port 502 --out paola_t1/results/modbus_t1.json --test-pcap modbus_ids/illegal_func.pcapng
```

An unknown group is not automatically an attack. This command reports group
assignments, not attack-detection accuracy.

To repeat the additional Modbus experiments, with `validate.py` and the repository's
Modbus scripts and captures available:

```bash
python -m paola_t1.validate
```

## Results from my initial tests

All 10 automated tests passed. They check input validation, repeatable grouping,
handling of unknown patterns, independence from metadata, and preservation of the
original records. They also check that assigning groups does not retrain the model.

With the default entropy threshold of 1.5, I obtained these results on the data
reserved for testing:

| Data | Result |
|---|---|
| Synthetic Modbus: 1,200 messages | Three groups matching function codes 3, 4, and 6. |
| Captured Modbus: 595 requests | Two groups: 548 reads with function code 3 and 47 writes with function code 6. |
| OPC UA: 59 TCP payloads | 56 assigned to learned groups and 3 marked unknown. |

For the two Modbus tests, all test messages were assigned, and the groups matched
the function-code categories. I used the function codes only to check the results
after clustering, not to train the model. These results measure grouping quality,
not attack detection.

The threshold matters. At an entropy threshold of 0.75, the synthetic test merged
function codes 3 and 4 into one group. Its purity dropped to about 58.3%. Purity
measures how much each group contains messages from just one reference category.

I have not verified the OPC UA groups against service-type labels, so I do not
claim that each group represents a particular OPC UA operation. These initial
results need further testing across independent captures and more varied traffic.

## Limitations of this clustering method

- Grouping by length can split one message type into several groups if its size
  changes.
- A data field or a slowly changing counter can look like a message-type indicator.
  In the captured Modbus test, the selected positions included bytes associated
  with the address and value, as well as the function code. More varied captures
  are needed to check whether these patterns still work.
- Constant byte positions are not selected because they do not distinguish groups
  of the same length. If no positions are selected, grouping uses length alone.
  Changes in ignored bytes may therefore go unnoticed.
- Rare but valid messages can be marked unknown when there are too few examples.
- The capture loader reads individual TCP payloads. It does not rebuild TCP
  streams. A message can span several packets, and one packet can contain several
  messages. Retransmissions can also repeat data. These cases need to be handled
  before treating every payload as a complete application message.

## Boundary-inference limitations

Boundary inference means finding where one field ends and the next begins inside
a message. One important limitation is **under-segmentation of adjacent constant
fields**: the method can combine two neighboring fields into one.

For example, suppose two separate two-byte fields always contain zeros:

```text
Actual fields:  [00 00] [00 00]
Possible guess: [00 00 00 00]
```

The bytes do not change across the observed messages, so a method based on byte
variation has no clear evidence of the boundary in the middle. It may identify
one four-byte field instead of two two-byte fields.

The opposite can also happen. In one numeric field, the higher bytes may stay
constant while the lower bytes change. A variation-based method may incorrectly
split that single field into several fields.

Clustering helps by separating different message formats before field analysis,
but it does not solve every boundary problem. Within one group, bytes identifying
the message type may themselves become constant. Short captures, limited value
ranges, variable-length fields, and incomplete TCP messages can also make the
boundaries harder to identify.

To evaluate boundary inference, I would compare the predicted boundaries with
known reference boundaries and report precision, recall, and F1. The comparison
should state whether boundaries must match exactly and whether the start and end
of each message are counted. A boundary F1 score measures field separation, not
the percentage of attacks detected.

Capturing a wider range of normal operations and values can provide more evidence.
However, if two fields remain indistinguishable in the data, their separation
should be reported as uncertain rather than assumed to be correct.

## Connecting T1 to field inference

The helper `group_messages(messages, assignments)` groups the original records
without changing their contents or their order within each group. The next step
is to analyze each known group separately and learn its field layout. Records
marked `-1` should be kept for review.

This module currently runs separately from the detectors. Its grouping results
should not be presented as results from a fully integrated detection pipeline.

## Plan for the next evaluation

For the next round, I plan to:

1. Use captures covering the additional clients, shared process operations, and
   attack scenarios, together with normal traffic from the updated setup.
2. Verify attack labels using logs and connection information. The most frequent
   client port alone is not a reliable label when multiple normal clients exist.
3. Check TCP reconstruction and keep requests, responses, and independent
   connections distinguishable.
4. Use separate training, validation, and test sessions. Learn patterns from clean
   training data, choose settings using validation data, and keep the test set
   separate until the final evaluation.
5. Evaluate the connection between clustering, field inference, and detection.
   Report manually specified and automatically inferred field layouts separately.
6. Check that behavior rules account for reads covering multiple registers and
   use the appropriate device and session history.
7. Report detection and false-alarm results for each attack and protocol, including
   sample counts. Clearly distinguish scores per message from scores per time
   window.

The current experiments provide a starting point for that evaluation. They do not
replace testing with the expanded setup.
