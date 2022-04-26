# CIS 497 Spring 2022
# Parker Arrington
# Chandler Armagost
# Tristan Clark
# Eric Sternberg

# Realtime Anomaly Detection with pyshark for capture and netml for detection
# Classification of network traffic for outlier detection

from netml.pparser.parser import PCAP
from netml.utils.tool import load_data
import pyshark
import timeit

cont_going = True
capture = pyshark.LiveCapture(output_file="data/capture.pcap")
iter_count = 0
while cont_going:
    capture.sniff(timeout=5)
    start = timeit.timeit()
    pcap = PCAP(
        'data/capture.pcap',
        flow_ptks_thres=2,
        random_state=42,
        verbose=1,
    )
    # extract flows from pcap
    pcap.pcap2flows(q_interval=0.9)
    # extract features from each flow given feat_type
    pcap.flow2features('IAT', fft=False, header=False)
    (model, train_history) = load_data('out/OCSVM-results.dat')
    temp = model.predict(pcap.features)
    count = 0
    for x in temp:
        if x == -1:
            try:
                with open("possible_anomalies.csv", "a") as f:
                    temp_write = str(capture[count].ip)
                    temp_write = temp_write.replace("\n", ",").strip()
                    print("Anomaly Detected from " + str(capture[count].ip.src) + " to " + str(capture[count].ip.dst))
                    f.write(str(temp_write) + "\n")
            except:
                print("Could not Access Packet Layer")
        count += 1
    end = timeit.timeit()
    print("Total Down Time between Intervals: " + str(abs(end - start)))
    iter_count += 1
    # if statement is used to get out of loop for demo purposes
    if iter_count > 10:
        cont_going = False
