import pandas as pd
import joblib
from dash import Dash, html, dash_table, dcc
import dash_bootstrap_components as dbc
import plotly.express as px
from dash.dependencies import Input, Output
from threading import Thread, Event
import datetime
import time
import dash
import psutil
import subprocess
from scapy.all import sniff, IP, TCP, UDP
import statistics
import socket
from queue import Queue
import re
# Load the AI models
#binary_classifier = joblib.load("binary_classifier123456789.joblib")
#attack_classifier = joblib.load("multiclass_classifier123456789.joblib")


binary_classifier = joblib.load("binary_classifier_model2.joblib")
attack_classifier = joblib.load("attack_type_classifier_model2.joblib")
# Initialize Dash app
app = Dash(__name__, external_stylesheets=[dbc.themes.BOOTSTRAP,"https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0-beta3/css/all.min.css", dbc.themes.DARKLY])

# Queue for real-time data transfer
data_queue = Queue(maxsize=300)

# Event to stop the sniffing thread
stop_sniffing = Event()

# Function to detect active network interfaces
def detect_active_interfaces():
    interfaces = []
    for iface, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address != "127.0.0.1":
                interfaces.append((iface, addr.address))
                print("**************", iface, addr.address)
    return interfaces

# Function to select a specific interface
def select_interface(interface_name="Wi-Fi"):
    active_interfaces = detect_active_interfaces()
    for iface, ip in active_interfaces:
        if iface == interface_name:
            print(f"Using interface: {iface}, IP Address: {ip}")
            return iface, ip
    print(f"Interface '{interface_name}' not found. Please check the list.")
    return None, None

# Function to resolve IP to hostname
def resolve_hostname(ip_address):
    try:
        hostname = socket.gethostbyaddr(ip_address)[0]
    except (socket.herror, socket.gaierror):
        hostname = ip_address
    return hostname

# Function to measure latency and packet loss


def measure_latency_packet_loss(target_ip="8.8.8.8", ping_count=5):
    latencies = []
    lost_packets = 0

    for _ in range(ping_count):
        try:
            response = subprocess.run(
                ['ping', '-n', '1', '-w', '1000', target_ip],  # Adjusted for Windows
                capture_output=True, text=True, encoding='latin1'  # Ensure correct encoding
            )
            print("Ping response:\n", response.stdout)  # Debugging log

            # Extract latency using regex
            latency_match = re.search(r'temps=([0-9]+)\s*ms', response.stdout)
            if latency_match:
                latency = float(latency_match.group(1))
                latencies.append(latency)
            else:
                lost_packets += 1  # No response means packet lost
        except Exception as e:
            print(f"Ping command failed: {e}")
            lost_packets += 1
        time.sleep(0.2)

    average_latency = sum(latencies) / len(latencies) if latencies else 0
    packet_loss_percentage = (lost_packets / ping_count) * 100

    # Debugging logs
    print(f"Latencies: {latencies}")
    print(f"Lost Packets: {lost_packets}")
    print(f"Packet Loss (%): {packet_loss_percentage}")

    return average_latency, packet_loss_percentage, latencies

# Function to calculate jitter
def calculate_jitter(latencies):
    return statistics.stdev(latencies) if len(latencies) > 1 else 0.0

# Function to calculate throughput
def calculate_throughput(previous_bytes, current_bytes, interval_seconds):
    return (current_bytes - previous_bytes) * 8 / (1024 * 1024 * interval_seconds)  # Mbps

# Updated function to collect network data
def collect_network_data():
    interface, ip = select_interface("Wi-Fi")
    if not interface:
        print("No valid interface found.")
        return

    print(f"Using interface: {interface}, IP Address: {ip}")

    previous_sent = psutil.net_io_counters().bytes_sent
    previous_recv = psutil.net_io_counters().bytes_recv
    previous_time = time.time()

    while not stop_sniffing.is_set():
        try:
            # Measure network performance
            current_time = time.time()
            current_sent = psutil.net_io_counters().bytes_sent
            current_recv = psutil.net_io_counters().bytes_recv

            # Calculate throughput
            interval = current_time - previous_time
            throughput_sent = calculate_throughput(previous_sent, current_sent, interval)
            throughput_recv = calculate_throughput(previous_recv, current_recv, interval)
            total_throughput = throughput_sent + throughput_recv

            # Measure latency, jitter, and packet loss
            latency, packet_loss, latencies = measure_latency_packet_loss()
            jitter = calculate_jitter(latencies)

            # Bandwidth utilization
            bandwidth_utilization = (current_sent + current_recv) * 8 / (1024 * 1024)

            # Sniff packets
            packets = sniff(iface=interface, timeout=10, count=50, store=True)
            network_data = []

            for packet in packets:
                if IP in packet:
                    src_ip = packet[IP].src
                    dst_ip = packet[IP].dst
                    protocol = packet[IP].proto
                    src_port = packet[TCP].sport if TCP in packet else (packet[UDP].sport if UDP in packet else None)
                    dst_port = packet[TCP].dport if TCP in packet else (packet[UDP].dport if UDP in packet else None)
                    packet_size = len(packet)

                    network_data.append({
                        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'bytes_sent': current_sent,
                        'bytes_recv': current_recv,
                        'latency (ms)': latency,
                        'jitter (ms)': jitter,
                        'packet_loss': packet_loss,
                        'throughput (Mbps)': total_throughput,
                        'bandwidth_utilization (Mbps)': bandwidth_utilization,
                        'src_ip': src_ip,
                        'src_port': src_port,
                        'dst_ip': dst_ip,
                        'dst_port': dst_port,
                        'protocol': protocol,
                        'packet_size': packet_size
                    })
            
            # Add network_data to the queue
            if network_data:
                print(f"Captured {len(network_data)} packets")
                data_queue.put(network_data)
            else:
                print("No packets captured")
            
            # Update previous values
            previous_sent = current_sent
            previous_recv = current_recv
            previous_time = current_time

        except Exception as e:
            print(f"Error during packet collection: {e}")


# Function to classify data
def classify_real_time_data():
    while not stop_sniffing.is_set():
        if not data_queue.empty():
            data = data_queue.get()
            df = pd.DataFrame(data)

            # Ensure only AI model features are used
            ai_features = binary_classifier.feature_names_in_
            df['Is_Abnormal'] = binary_classifier.predict(df[ai_features])
            df['Status'] = df['Is_Abnormal'].apply(lambda x: 'Normal' if x == 0 else 'Abnormal')

            # Predict attack types for abnormal data
            abnormal_data = df[df['Is_Abnormal'] == 1]
            if not abnormal_data.empty:
                attack_predictions = attack_classifier.predict(abnormal_data[ai_features])
                df.loc[df['Is_Abnormal'] == 1, 'Attack_Type'] = [
                    ["DDoS", "BruteForce", "Spoofing", "MITM"][pred - 1] for pred in attack_predictions
                ]
            else:
                df['Attack_Type'] = "Normal"

            # Add processed data back to the queue
            data_queue.put(df.to_dict('records'))



# Initialize and start the thread
# Start data collection and classification threads
Thread(target=collect_network_data, daemon=True).start()
Thread(target=classify_real_time_data, daemon=True).start()





# Define threshold values for conditional formatting

#THRESHOLDS = { 
    #'bytes_sent': {'low': 1000000, 'high': 5000000},  # Adjusted to handle spikes in data transfer
   # 'bytes_recv': {'low': 1000000, 'high': 5000000},  # Similar adjustment for reception
  #  'latency (ms)': {'low': 10, 'high': 100},         # Reflects acceptable delay in most networks
 #   'jitter (ms)': {'low': 1, 'high': 20},            # Higher jitter thresholds for unstable environments
  #  'packet_loss': {'low': 0.0, 'high': 1.0},         # Up to 1% packet loss might be tolerable
  #  'throughput (Mbps)': {'low': 50, 'high': 2000},   # Wider range for varying network loads
#    'bandwidth_utilization (Mbps)': {'low': 0.1, 'high': 50},  # Based on typical network capacity
 #   'packet_size': {'low': 70, 'high': 1500},         # Ethernet MTU size range
#    'src_port': {'low': 0, 'high': 65535},            # Standard port range
 #   'dst_port': {'low': 0, 'high': 65535},            # Standard port range
#}


THRESHOLDS = { 
    'bytes_sent': {'low': 1_000_000, 'high': 500_000_000},  # Adjusted for observed traffic
    'bytes_recv': {'low': 1_000_000, 'high': 500_000_000},  # Adjusted for observed traffic
    'latency (ms)': {'low': 11, 'high': 50},                # Retain for stability
    'jitter (ms)': {'low': 2, 'high': 10},               # Retain for stability
    'packet_loss': {'low': 0.0, 'high': 0.05},             # Retain as is
    'throughput (Mbps)': {'low': 2000, 'high': 3000},       # Adjusted for high traffic scenarios
    'bandwidth_utilization (Mbps)': {'low': 1, 'high': 100}, # Adjusted for observed utilization
    'packet_size': {'low': 64, 'high': 1500},              # Standard MTU size
    'src_port': {'low': 0, 'high': 65535},                 # Standard port range
    'dst_port': {'low': 0, 'high': 65535},                 # Standard port range
}



# Generate conditional styling for each parameter based on thresholds
style_data_conditional = []

style_data_conditional.extend([
    {
        'if': {'filter_query': '{Is_Abnormal} = 0', 'column_id': 'Status'},
        'backgroundColor': '#2ECC40',
        'color': 'white'
    },
    {
        'if': {'filter_query': '{Is_Abnormal} = 1', 'column_id': 'Status'},
        'backgroundColor': '#FF4136',
        'color': 'white'
    }
])

for column, thresholds in THRESHOLDS.items():
    style_data_conditional.extend([
        {
            'if': {
                'filter_query': f'{{{column}}} >= {thresholds["high"]}',
                'column_id': column
            },
            'backgroundColor': '#DC4405',
            'color': 'white'
        },
        {
            'if': {
                'filter_query': f'{{{column}}} < {thresholds["high"]} && {{{column}}} >= {thresholds["low"]}',
                'column_id': column
            },
            'backgroundColor': '#FF851B',
            'color': 'black'
        },
        {
            'if': {
                'filter_query': f'{{{column}}} < {thresholds["low"]}',
                'column_id': column
            },
            'backgroundColor': '#2ECC40',
            'color': 'white'
        }
    ])


# Sidebar with logo and navigation
sidebar = dbc.Nav(
    [
        html.Img(src="assets/amel.jpg", style={"width": "80%", "margin-bottom": "50px", "display": "block"}),  # Add company logo
        
         # Navigation links with icons
        dbc.NavLink([html.I(className="fas fa-clock", style={"margin-right": "10px"}), "Latency "], 
                    href="#latency", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-upload", style={"margin-right": "10px"}), "Bytes Sent "], 
                    href="#bytes_sent", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-download", style={"margin-right": "10px"}), "Bytes Received "], 
                    href="#bytes_recv", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-random", style={"margin-right": "10px"}), "Jitter "], 
                    href="#jitter", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-tachometer-alt", style={"margin-right": "10px"}), "Throughput "], 
                    href="#throughput", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-wifi", style={"margin-right": "10px"}), "Bandwidth Utilization "], 
                    href="#bandwidth_utilization", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-cube", style={"margin-right": "10px"}), "Packet Size"], 
                    href="#packet_size", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-exclamation-circle", style={"margin-right": "10px"}), "Normal vs Abnormal Traffic"], 
                    href="#normal_vs_abnormal", external_link=True, style={"color": "#C8C9C7"}),
        
        dbc.NavLink([html.I(className="fas fa-shield-alt", style={"margin-right": "10px"}), "Types of Attacks"], 
                    href="#attack_types", external_link=True, style={"color": "#C8C9C7"}),



    ],
    vertical=True,
    pills=True,
    style={"background-color": "#343a40", "padding": "10px", "color": "white", "position": "fixed", "top": 0, "left": 0, "bottom": 0, "width": "15%"}
)




# Dashboard layout
# Dashboard layout
app.layout = dbc.Container(
    [
        html.Div(
            [
                html.I(className="fas fa-sun", style={"margin-right": "8px"}),
                dbc.Switch(id="theme-toggle", value=False, style={"margin-left": "8px"}),
                html.I(className="fas fa-moon", style={"margin-left": "8px"}),
            ],
            style={"display": "flex", "align-items": "center", "justify-content": "flex-end", "padding": "10px"},
        ),
        sidebar,
        dbc.Container(
            [
                html.H2("Real-Time Network Monitoring Dashboard", className="text-center text-primary mb-4"),
                dbc.Row(
                    dbc.Col(
                        dash_table.DataTable(
                            id='data-table',
                            columns=[
                                {"name": col, "id": col} for col in [
                                    'timestamp', 'bytes_sent', 'bytes_recv', 'latency (ms)', 'jitter (ms)',
                                    'packet_loss', 'throughput (Mbps)', 'bandwidth_utilization (Mbps)',
                                    'src_ip', 'src_port', 'dst_ip', 'dst_port', 'protocol', 'packet_size',
                                    'Status', 'Attack_Type'
                                ]
                            ],
                            style_data_conditional=style_data_conditional,
                            page_size=10,
                            style_table={'overflowX': 'auto'},
                            style_cell={'textAlign': 'left', 'color': 'black'},
                            style_header={'fontWeight': 'bold', 'backgroundColor': 'lightgrey'},
                        ),
                        width=10
                    ), className="mb-4",
                ),
                # Add empty graphs for dynamic updates
                dbc.Row(
                    [
                        dbc.Col(dcc.Graph(id="latency", figure={}), width=5),
                        dbc.Col(dcc.Graph(id="bytes_sent", figure={}), width=5),
                    ], className="mb-4"
                ),
                dbc.Row(
                    [
                        dbc.Col(dcc.Graph(id="bytes_recv", figure={}), width=5),
                        dbc.Col(dcc.Graph(id="jitter", figure={}), width=5),
                    ], className="mb-4"
                ),
                dbc.Row(
                    [
                        dbc.Col(dcc.Graph(id="throughput", figure={}), width=5),
                        dbc.Col(dcc.Graph(id="bandwidth_utilization", figure={}), width=5),
                    ], className="mb-4"
                ),
                dbc.Row(
                    dbc.Col(dcc.Graph(id="packet_size", figure={}), width=10), className="mb-4"
                ),
                dbc.Row(
                    [
                        dbc.Col(dcc.Graph(id="normal_vs_abnormal", figure={}), width=5),
                        dbc.Col(dcc.Graph(id="attack_types", figure={}), width=5),
                    ], className="mb-4"
                ),
            ],
            style={"margin-left": "18%"}
        ),
        dcc.Interval(id='interval', interval=1000, n_intervals=0)
    ],
    fluid=True
)


# Update dashboard with real-time data
@app.callback(
    [Output('data-table', 'data'),
     Output('latency', 'figure'),
     Output('bytes_sent', 'figure'),
     Output('bytes_recv', 'figure'),
     Output('normal_vs_abnormal', 'figure'),
     Output('attack_types', 'figure')],
    [Input('interval', 'n_intervals')]
)
def update_dashboard(n):
    if not data_queue.empty():
        classified_data = data_queue.get()
        df = pd.DataFrame(classified_data)

        # Ensure 'Status' and 'Attack_Type' columns exist
        if 'Status' not in df.columns:
            df['Status'] = 'Unknown'  # Placeholder for missing data
        if 'Attack_Type' not in df.columns:
            df['Attack_Type'] = 'Unknown'  # Placeholder for missing data

        # Create figures
        latency_fig = px.line(df, x='timestamp', y='latency (ms)', title="Latency Over Time")
        bytes_sent_fig = px.line(df, x='timestamp', y='bytes_sent', title="Bytes Sent Over Time")
        bytes_recv_fig = px.line(df, x='timestamp', y='bytes_recv', title="Bytes Received Over Time")
        normal_vs_abnormal_fig = px.pie(df, names='Status', title="Normal vs Abnormal Traffic")
        attack_types_fig = px.pie(df[df['Attack_Type'] != "Normal"], names='Attack_Type', title="Types of Attacks")

        return (
            df.to_dict('records'),
            latency_fig,
            bytes_sent_fig,
            bytes_recv_fig,
            normal_vs_abnormal_fig,
            attack_types_fig,
        )

    return dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update, dash.no_update

# Start the Dash server
if __name__ == "__main__":
    app.run_server(debug=True, port=8051)
