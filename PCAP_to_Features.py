# CIS 497 Spring 2022
# Parker Arrington
# Chandler Armagost
# Tristan Clark
# Eric Sternberg

# Used to teach the model to use for anomaly detection
# PCAP to Features

from netml.pparser.parser import PCAP
from netml.ndm.model import MODEL
from netml.ndm.ocsvm import OCSVM
from netml.utils.tool import dump_data, load_data

pcap = PCAP(
    'data/Monday-WorkingHours.pcap',
    flow_ptks_thres=2,
    random_state=42,
    verbose=1,
)

# extract flows from pcap
pcap.pcap2flows(q_interval=0.9)

# extract features from each flow via IAT
pcap.flow2features('IAT', fft=False, header=False)

# dump data to disk
dump_data((pcap.features, pcap.labels), out_file='out/IAT-features.dat')


# # Features to Models


RANDOM_STATE = 42

# load data
(features, labels) = load_data('out/IAT-features.dat')

# create detection model
ocsvm = OCSVM(kernel='rbf', nu=0.5, random_state=RANDOM_STATE)
ocsvm.name = 'OCSVM'
ndm = MODEL(ocsvm, score_metric='auc', verbose=10, random_state=RANDOM_STATE)

# train the model from the train set
ndm.train(features)

# dump data to disk
dump_data((ocsvm, ndm.history), out_file='out/OCSVM-results.dat')
