# CIS 497 Spring 2022
# Parker Arrington
# Chandler Armagost
# Tristan Clark
# Eric Sternberg

# Used to test the model to determine models accuracy

from netml.pparser.parser import PCAP
from netml.utils.tool import load_data
import pyshark


def run_test_model_calc(pcap_data, model_data):
    capture = pyshark.FileCapture(pcap_data)
    pcap = PCAP(pcap_data, flow_ptks_thres=2, random_state=42, verbose=1)
    pcap.pcap2flows(q_interval=0.9)
    pcap.flow2features('IAT', fft=False, header=False)
    (model, train_history) = load_data(model_data)
    print("Starting Prediction")
    pcap_classifications = 0
    pcap_classifications = model.predict(pcap.features)
    print("Prediction Complete")
    count = 0
    found_attacks_on_neg = 0
    found_attacks_on_pos = 0
    false_positive_attacks_on_neg = 0
    false_positive_attacks_on_pos = 0
    for x in pcap_classifications:
        print(x)
        if x == -1:
            try:
                if capture[count].ip.src == "205.174.165.73" or capture[count].ip.dst == "205.174.165.73" or \
                        capture[count].ip.src == "205.174.165.80" or capture[count].ip.dst == "205.174.165.80":
                    found_attacks_on_neg += 1
                else:
                    false_positive_attacks_on_neg += 1
            except:
                print("Could not Access Packet IP Layer")
        elif x == 1:
            try:
                if capture[count].ip.src == "205.174.165.73" or capture[count].ip.dst == "205.174.165.73" or \
                        capture[count].ip.src == "205.174.165.80" or capture[count].ip.dst == "205.174.165.80":
                    found_attacks_on_pos += 1
                else:
                    false_positive_attacks_on_pos += 1
            except:
                print("Could not Access Packet IP Layer")
        count += 1

    percent_correct_neg = found_attacks_on_neg / false_positive_attacks_on_neg * 100
    percent_correct_pos = found_attacks_on_pos / false_positive_attacks_on_pos * 100
    with open("out/testing_output.txt", "a") as f:
        f.write(str(model_data) + ": percent correct on -1: " + str(percent_correct_neg) +
                ": percent correct on 1: " + str(percent_correct_pos) + "\n")


data_pcap = "data/Tuesday-Small-WorkingHours.pcap"
model_list = ["out/Monday-OCSVM-model.dat", "out/Tuesday-OCSVM-model.dat"]
for model in model_list:
    print(data_pcap)
    print(model)
    run_test_model_calc(data_pcap, model)
    print("\nFinished Test " + model + "\n\n\n\n\n")

