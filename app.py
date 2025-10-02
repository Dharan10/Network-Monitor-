"""
Network Flow Monitor - Modern GUI Application
A comprehensive network monitoring tool with visual packet flow analysis
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import time
import json
from datetime import datetime
from collections import defaultdict, deque
import queue
from scapy.all import sniff, get_if_list, Ether, IP, TCP, UDP, ARP
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.animation import FuncAnimation
import numpy as np

class NetworkMonitor:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Network Flow Monitor")
        self.root.geometry("1200x800")
        self.root.configure(bg='#2b2b2b')
        
        # Data structures
        self.packet_queue = queue.Queue()
        self.flows = defaultdict(lambda: {
            'packets': 0, 'bytes': 0, 'first_seen': time.time(), 'last_seen': time.time()
        })
        self.packet_history = deque(maxlen=100)
        self.protocol_stats = defaultdict(int)
        self.capture_running = False
        self.selected_interface = None
        
        # Configuration
        self.config = {
            'capture_filter': 'tcp or udp',
            'max_packets': 1000,
            'update_interval': 1.0,
            'alert_threshold': 100
        }
        
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the main UI components"""
        # Style configuration
        style = ttk.Style()
        style.theme_use('clam')
        style.configure('TLabel', background='#2b2b2b', foreground='white')
        style.configure('TButton', background='#404040', foreground='white')
        style.configure('TFrame', background='#2b2b2b')
        
        # Main notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        # Create tabs
        self.create_interface_tab()
        self.create_monitor_tab()
        self.create_flows_tab()
        self.create_visual_tab()
        self.create_settings_tab()
        
    def create_interface_tab(self):
        """Create interface selection tab"""
        self.interface_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.interface_frame, text="Interface Selection")
        
        # Title
        title_label = tk.Label(
            self.interface_frame, 
            text="Network Interface Selection",
            font=('Arial', 16, 'bold'),
            bg='#2b2b2b',
            fg='white'
        )
        title_label.pack(pady=20)
        
        # Interface list
        self.interface_listbox = tk.Listbox(
            self.interface_frame,
            font=('Courier', 12),
            bg='#404040',
            fg='white',
            selectbackground='#606060',
            height=10
        )
        self.interface_listbox.pack(pady=10, padx=20, fill='both', expand=True)
        
        # Refresh interfaces button
        refresh_btn = tk.Button(
            self.interface_frame,
            text="🔄 Refresh Interfaces",
            command=self.refresh_interfaces,
            bg='#404040',
            fg='white',
            font=('Arial', 12),
            pady=5
        )
        refresh_btn.pack(pady=5)
        
        # Select button
        select_btn = tk.Button(
            self.interface_frame,
            text="✓ Select Interface",
            command=self.select_interface,
            bg='#28a745',
            fg='white',
            font=('Arial', 12, 'bold'),
            pady=8
        )
        select_btn.pack(pady=10)
        
        # Status label
        self.interface_status = tk.Label(
            self.interface_frame,
            text="No interface selected",
            bg='#2b2b2b',
            fg='#ffc107',
            font=('Arial', 11)
        )
        self.interface_status.pack(pady=5)
        
        # Load interfaces on startup
        self.refresh_interfaces()
        
    def create_monitor_tab(self):
        """Create main monitoring tab"""
        self.monitor_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.monitor_frame, text="Live Monitor")
        
        # Control panel
        control_frame = tk.Frame(self.monitor_frame, bg='#2b2b2b')
        control_frame.pack(fill='x', padx=10, pady=5)
        
        self.start_btn = tk.Button(
            control_frame,
            text="▶ Start Capture",
            command=self.start_capture,
            bg='#28a745',
            fg='white',
            font=('Arial', 12, 'bold')
        )
        self.start_btn.pack(side='left', padx=5)
        
        self.stop_btn = tk.Button(
            control_frame,
            text="⏹ Stop Capture",
            command=self.stop_capture,
            bg='#dc3545',
            fg='white',
            font=('Arial', 12, 'bold'),
            state='disabled'
        )
        self.stop_btn.pack(side='left', padx=5)
        
        # Statistics frame
        stats_frame = tk.Frame(self.monitor_frame, bg='#404040', relief='raised', bd=2)
        stats_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(
            stats_frame,
            text="📊 Live Statistics",
            font=('Arial', 14, 'bold'),
            bg='#404040',
            fg='white'
        ).pack(pady=5)
        
        stats_inner = tk.Frame(stats_frame, bg='#404040')
        stats_inner.pack(fill='x', padx=10, pady=5)
        
        # Statistics labels
        self.stats_labels = {}
        stats = ['Total Packets', 'Active Flows', 'TCP Packets', 'UDP Packets', 'Bytes/sec']
        
        for i, stat in enumerate(stats):
            frame = tk.Frame(stats_inner, bg='#404040')
            frame.grid(row=i//3, column=i%3, padx=10, pady=5, sticky='w')
            
            tk.Label(
                frame,
                text=f"{stat}:",
                bg='#404040',
                fg='#aaa',
                font=('Arial', 10)
            ).pack()
            
            self.stats_labels[stat] = tk.Label(
                frame,
                text="0",
                bg='#404040',
                fg='#00ff00',
                font=('Arial', 12, 'bold')
            )
            self.stats_labels[stat].pack()
        
        # Packet log
        log_frame = tk.Frame(self.monitor_frame, bg='#2b2b2b')
        log_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        tk.Label(
            log_frame,
            text="📡 Live Packet Stream",
            font=('Arial', 14, 'bold'),
            bg='#2b2b2b',
            fg='white'
        ).pack(anchor='w')
        
        self.packet_text = scrolledtext.ScrolledText(
            log_frame,
            bg='#1e1e1e',
            fg='#00ff00',
            font=('Courier', 9),
            wrap=tk.WORD
        )
        self.packet_text.pack(fill='both', expand=True, pady=5)
        
    def create_flows_tab(self):
        """Create network flows tab"""
        self.flows_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.flows_frame, text="Network Flows")
        
        # Flows table
        tk.Label(
            self.flows_frame,
            text="🌐 Active Network Flows",
            font=('Arial', 16, 'bold'),
            bg='#2b2b2b',
            fg='white'
        ).pack(pady=10)
        
        # Treeview for flows
        columns = ('Source', 'Destination', 'Protocol', 'Packets', 'Bytes', 'Duration')
        self.flows_tree = ttk.Treeview(self.flows_frame, columns=columns, show='headings', height=15)
        
        for col in columns:
            self.flows_tree.heading(col, text=col)
            self.flows_tree.column(col, width=120, anchor='center')
        
        # Scrollbar for flows tree
        flows_scroll = ttk.Scrollbar(self.flows_frame, orient='vertical', command=self.flows_tree.yview)
        self.flows_tree.configure(yscrollcommand=flows_scroll.set)
        
        # Pack flows tree and scrollbar
        tree_frame = tk.Frame(self.flows_frame, bg='#2b2b2b')
        tree_frame.pack(fill='both', expand=True, padx=10, pady=5)
        
        self.flows_tree.pack(side='left', fill='both', expand=True)
        flows_scroll.pack(side='right', fill='y')
        
        # Flow details
        details_frame = tk.Frame(self.flows_frame, bg='#404040', relief='raised', bd=2)
        details_frame.pack(fill='x', padx=10, pady=5)
        
        tk.Label(
            details_frame,
            text="Flow Details",
            font=('Arial', 12, 'bold'),
            bg='#404040',
            fg='white'
        ).pack(pady=5)
        
        self.flow_details = tk.Text(
            details_frame,
            height=6,
            bg='#1e1e1e',
            fg='white',
            font=('Courier', 10)
        )
        self.flow_details.pack(fill='x', padx=10, pady=5)
        
        # Bind selection event
        self.flows_tree.bind('<<TreeviewSelect>>', self.on_flow_select)
        
    def create_visual_tab(self):
        """Create visualization tab with charts"""
        self.visual_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.visual_frame, text="Visual Analysis")
        
        # Create matplotlib figure
        self.fig, ((self.ax1, self.ax2), (self.ax3, self.ax4)) = plt.subplots(2, 2, figsize=(12, 8))
        self.fig.patch.set_facecolor('#2b2b2b')
        
        for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
            ax.set_facecolor('#1e1e1e')
            ax.tick_params(colors='white')
            ax.spines['bottom'].set_color('white')
            ax.spines['top'].set_color('white')
            ax.spines['left'].set_color('white')
            ax.spines['right'].set_color('white')
        
        # Setup plots
        self.ax1.set_title('Packets per Second', color='white', fontsize=12)
        self.ax1.set_ylabel('Packets/sec', color='white')
        
        self.ax2.set_title('Protocol Distribution', color='white', fontsize=12)
        
        self.ax3.set_title('Top Talkers', color='white', fontsize=12)
        self.ax3.set_ylabel('Bytes', color='white')
        
        self.ax4.set_title('Traffic Timeline', color='white', fontsize=12)
        self.ax4.set_ylabel('Bytes', color='white')
        
        # Embed plot in tkinter
        self.canvas = FigureCanvasTkAgg(self.fig, self.visual_frame)
        self.canvas.draw()
        self.canvas.get_tk_widget().pack(fill='both', expand=True)
        
        # Initialize data for plots
        self.time_data = deque(maxlen=60)
        self.packet_rate_data = deque(maxlen=60)
        self.byte_rate_data = deque(maxlen=60)
        
    def create_settings_tab(self):
        """Create settings configuration tab"""
        self.settings_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_frame, text="Settings")
        
        # Title
        tk.Label(
            self.settings_frame,
            text="⚙️ Configuration Settings",
            font=('Arial', 16, 'bold'),
            bg='#2b2b2b',
            fg='white'
        ).pack(pady=20)
        
        # Settings form
        settings_form = tk.Frame(self.settings_frame, bg='#404040', relief='raised', bd=2)
        settings_form.pack(fill='both', expand=True, padx=20, pady=10)
        
        # Capture filter
        tk.Label(
            settings_form,
            text="Capture Filter (BPF):",
            bg='#404040',
            fg='white',
            font=('Arial', 12, 'bold')
        ).grid(row=0, column=0, padx=10, pady=10, sticky='w')
        
        self.filter_entry = tk.Entry(
            settings_form,
            font=('Courier', 11),
            width=40,
            bg='#1e1e1e',
            fg='white',
            insertbackground='white'
        )
        self.filter_entry.insert(0, self.config['capture_filter'])
        self.filter_entry.grid(row=0, column=1, padx=10, pady=10)
        
        # Max packets
        tk.Label(
            settings_form,
            text="Max Packets in Memory:",
            bg='#404040',
            fg='white',
            font=('Arial', 12, 'bold')
        ).grid(row=1, column=0, padx=10, pady=10, sticky='w')
        
        self.max_packets_entry = tk.Entry(
            settings_form,
            font=('Arial', 11),
            width=20,
            bg='#1e1e1e',
            fg='white',
            insertbackground='white'
        )
        self.max_packets_entry.insert(0, str(self.config['max_packets']))
        self.max_packets_entry.grid(row=1, column=1, padx=10, pady=10, sticky='w')
        
        # Update interval
        tk.Label(
            settings_form,
            text="Update Interval (seconds):",
            bg='#404040',
            fg='white',
            font=('Arial', 12, 'bold')
        ).grid(row=2, column=0, padx=10, pady=10, sticky='w')
        
        self.interval_entry = tk.Entry(
            settings_form,
            font=('Arial', 11),
            width=20,
            bg='#1e1e1e',
            fg='white',
            insertbackground='white'
        )
        self.interval_entry.insert(0, str(self.config['update_interval']))
        self.interval_entry.grid(row=2, column=1, padx=10, pady=10, sticky='w')
        
        # Alert threshold
        tk.Label(
            settings_form,
            text="Alert Threshold (packets/sec):",
            bg='#404040',
            fg='white',
            font=('Arial', 12, 'bold')
        ).grid(row=3, column=0, padx=10, pady=10, sticky='w')
        
        self.threshold_entry = tk.Entry(
            settings_form,
            font=('Arial', 11),
            width=20,
            bg='#1e1e1e',
            fg='white',
            insertbackground='white'
        )
        self.threshold_entry.insert(0, str(self.config['alert_threshold']))
        self.threshold_entry.grid(row=3, column=1, padx=10, pady=10, sticky='w')
        
        # Buttons frame
        btn_frame = tk.Frame(settings_form, bg='#404040')
        btn_frame.grid(row=4, column=0, columnspan=2, pady=20)
        
        # Save button
        save_btn = tk.Button(
            btn_frame,
            text="💾 Save Settings",
            command=self.save_settings,
            bg='#28a745',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=20
        )
        save_btn.pack(side='left', padx=10)
        
        # Reset button
        reset_btn = tk.Button(
            btn_frame,
            text="🔄 Reset to Defaults",
            command=self.reset_settings,
            bg='#ffc107',
            fg='black',
            font=('Arial', 12, 'bold'),
            padx=20
        )
        reset_btn.pack(side='left', padx=10)
        
        # Export config button
        export_btn = tk.Button(
            btn_frame,
            text="📤 Export Config",
            command=self.export_config,
            bg='#17a2b8',
            fg='white',
            font=('Arial', 12, 'bold'),
            padx=20
        )
        export_btn.pack(side='left', padx=10)
        
    def refresh_interfaces(self):
        """Refresh the list of available network interfaces"""
        try:
            self.interface_listbox.delete(0, tk.END)
            interfaces = get_if_list()
            
            for i, interface in enumerate(interfaces):
                display_text = f"{i}: {interface}"
                self.interface_listbox.insert(tk.END, display_text)
                
            self.interface_status.config(text=f"Found {len(interfaces)} interfaces")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to get interfaces: {str(e)}")
            
    def select_interface(self):
        """Select the chosen interface for monitoring"""
        selection = self.interface_listbox.curselection()
        if not selection:
            messagebox.showwarning("Warning", "Please select an interface first")
            return
            
        try:
            interfaces = get_if_list()
            selected_index = selection[0]
            self.selected_interface = interfaces[selected_index]
            
            self.interface_status.config(
                text=f"Selected: {self.selected_interface}",
                fg='#28a745'
            )
            
            messagebox.showinfo(
                "Interface Selected", 
                f"Interface '{self.selected_interface}' selected successfully!\n\nYou can now go to the 'Live Monitor' tab to start capturing packets."
            )
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to select interface: {str(e)}")
            
    def packet_handler(self, packet):
        """Handle captured packets"""
        try:
            if not self.capture_running:
                return
                
            # Extract packet information
            packet_info = self.extract_packet_info(packet)
            if packet_info:
                self.packet_queue.put(packet_info)
                
        except Exception as e:
            print(f"Error processing packet: {e}")
            
    def extract_packet_info(self, packet):
        """Extract relevant information from a packet"""
        info = {}
        
        try:
            info['timestamp'] = time.time()
            info['length'] = len(packet)
            
            if Ether in packet:
                info['eth_src'] = packet[Ether].src
                info['eth_dst'] = packet[Ether].dst
                
            if IP in packet:
                info['ip_src'] = packet[IP].src
                info['ip_dst'] = packet[IP].dst
                info['protocol'] = packet[IP].proto
                
                if TCP in packet:
                    info['src_port'] = packet[TCP].sport
                    info['dst_port'] = packet[TCP].dport
                    info['protocol_name'] = 'TCP'
                elif UDP in packet:
                    info['src_port'] = packet[UDP].sport
                    info['dst_port'] = packet[UDP].dport
                    info['protocol_name'] = 'UDP'
                else:
                    info['protocol_name'] = f"IP({packet[IP].proto})"
                    
            elif ARP in packet:
                info['protocol_name'] = 'ARP'
                info['ip_src'] = packet[ARP].psrc
                info['ip_dst'] = packet[ARP].pdst
                
            return info
            
        except Exception as e:
            print(f"Error extracting packet info: {e}")
            return None
            
    def start_capture(self):
        """Start packet capture"""
        if not self.selected_interface:
            messagebox.showwarning("Warning", "Please select an interface first")
            return
            
        try:
            self.capture_running = True
            self.start_btn.config(state='disabled')
            self.stop_btn.config(state='normal')
            
            # Start capture thread
            self.capture_thread = threading.Thread(
                target=self.capture_packets,
                daemon=True
            )
            self.capture_thread.start()
            
            # Start UI update thread
            self.update_thread = threading.Thread(
                target=self.update_ui,
                daemon=True
            )
            self.update_thread.start()
            
            self.packet_text.insert(tk.END, f"🚀 Started capture on {self.selected_interface}\n")
            self.packet_text.see(tk.END)
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start capture: {str(e)}")
            self.stop_capture()
            
    def capture_packets(self):
        """Capture packets in a separate thread"""
        try:
            sniff(
                iface=self.selected_interface,
                prn=self.packet_handler,
                filter=self.config['capture_filter'],
                stop_filter=lambda x: not self.capture_running
            )
        except Exception as e:
            print(f"Capture error: {e}")
            
    def stop_capture(self):
        """Stop packet capture"""
        self.capture_running = False
        self.start_btn.config(state='normal')
        self.stop_btn.config(state='disabled')
        
        self.packet_text.insert(tk.END, "⏹ Capture stopped\n")
        self.packet_text.see(tk.END)
        
    def update_ui(self):
        """Update UI with captured packet data"""
        packet_count = 0
        last_update = time.time()
        bytes_per_sec = 0
        
        while self.capture_running:
            try:
                # Process queued packets
                packets_this_second = []
                
                while not self.packet_queue.empty():
                    packet_info = self.packet_queue.get_nowait()
                    packets_this_second.append(packet_info)
                    packet_count += 1
                    
                    # Update packet history
                    self.packet_history.append(packet_info)
                    
                    # Update protocol stats
                    proto = packet_info.get('protocol_name', 'Unknown')
                    self.protocol_stats[proto] += 1
                    
                    # Update flows
                    self.update_flows(packet_info)
                    
                    # Display packet in log
                    self.display_packet(packet_info)
                    
                # Update statistics every second
                current_time = time.time()
                if current_time - last_update >= 1.0:
                    # Calculate rates
                    pps = len(packets_this_second)
                    bps = sum(p.get('length', 0) for p in packets_this_second)
                    
                    # Update stats labels
                    self.update_stats(packet_count, pps, bps)
                    
                    # Update visualizations
                    self.update_visualizations(current_time, pps, bps)
                    
                    last_update = current_time
                    packets_this_second = []
                    
                time.sleep(0.1)  # Small delay to prevent excessive CPU usage
                
            except queue.Empty:
                continue
            except Exception as e:
                print(f"UI update error: {e}")
                
    def update_flows(self, packet_info):
        """Update flow information"""
        if 'ip_src' not in packet_info or 'ip_dst' not in packet_info:
            return
            
        # Create flow key (normalize direction)
        src_ip = packet_info['ip_src']
        dst_ip = packet_info['ip_dst']
        src_port = packet_info.get('src_port', 0)
        dst_port = packet_info.get('dst_port', 0)
        protocol = packet_info.get('protocol_name', 'Unknown')
        
        if src_ip < dst_ip:
            flow_key = (src_ip, src_port, dst_ip, dst_port, protocol)
        else:
            flow_key = (dst_ip, dst_port, src_ip, src_port, protocol)
            
        # Update flow stats
        flow = self.flows[flow_key]
        flow['packets'] += 1
        flow['bytes'] += packet_info.get('length', 0)
        flow['last_seen'] = time.time()
        
    def display_packet(self, packet_info):
        """Display packet information in the log"""
        timestamp = datetime.fromtimestamp(packet_info['timestamp']).strftime('%H:%M:%S.%f')[:-3]
        
        if 'ip_src' in packet_info and 'ip_dst' in packet_info:
            if 'src_port' in packet_info:
                log_line = f"[{timestamp}] {packet_info['protocol_name']} {packet_info['ip_src']}:{packet_info['src_port']} -> {packet_info['ip_dst']}:{packet_info['dst_port']} ({packet_info['length']} bytes)\n"
            else:
                log_line = f"[{timestamp}] {packet_info['protocol_name']} {packet_info['ip_src']} -> {packet_info['ip_dst']} ({packet_info['length']} bytes)\n"
        else:
            log_line = f"[{timestamp}] {packet_info.get('protocol_name', 'Unknown')} ({packet_info['length']} bytes)\n"
            
        self.packet_text.insert(tk.END, log_line)
        
        # Limit text widget size
        lines = int(self.packet_text.index('end-1c').split('.')[0])
        if lines > 1000:
            self.packet_text.delete('1.0', '100.0')
            
        self.packet_text.see(tk.END)
        
    def update_stats(self, total_packets, pps, bps):
        """Update statistics labels"""
        try:
            self.stats_labels['Total Packets'].config(text=f"{total_packets:,}")
            self.stats_labels['Active Flows'].config(text=f"{len(self.flows):,}")
            self.stats_labels['TCP Packets'].config(text=f"{self.protocol_stats.get('TCP', 0):,}")
            self.stats_labels['UDP Packets'].config(text=f"{self.protocol_stats.get('UDP', 0):,}")
            self.stats_labels['Bytes/sec'].config(text=f"{bps:,}")
            
            # Update flows tree
            self.update_flows_tree()
            
        except Exception as e:
            print(f"Stats update error: {e}")
            
    def update_flows_tree(self):
        """Update the flows treeview"""
        try:
            # Clear existing items
            for item in self.flows_tree.get_children():
                self.flows_tree.delete(item)
                
            # Sort flows by packet count
            sorted_flows = sorted(
                self.flows.items(),
                key=lambda x: x[1]['packets'],
                reverse=True
            )[:50]  # Show top 50 flows
            
            for flow_key, flow_data in sorted_flows:
                src_ip, src_port, dst_ip, dst_port, protocol = flow_key
                
                source = f"{src_ip}:{src_port}" if src_port else src_ip
                destination = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                duration = f"{flow_data['last_seen'] - flow_data['first_seen']:.1f}s"
                
                self.flows_tree.insert('', 'end', values=(
                    source,
                    destination,
                    protocol,
                    flow_data['packets'],
                    flow_data['bytes'],
                    duration
                ))
                
        except Exception as e:
            print(f"Flows tree update error: {e}")
            
    def update_visualizations(self, current_time, pps, bps):
        """Update the visualization charts"""
        try:
            # Update time series data
            self.time_data.append(current_time)
            self.packet_rate_data.append(pps)
            self.byte_rate_data.append(bps)
            
            # Update packet rate plot
            self.ax1.clear()
            if len(self.time_data) > 1:
                times = [t - self.time_data[0] for t in self.time_data]
                self.ax1.plot(times, list(self.packet_rate_data), 'g-', linewidth=2)
            self.ax1.set_title('Packets per Second', color='white', fontsize=12)
            self.ax1.set_ylabel('Packets/sec', color='white')
            self.ax1.set_facecolor('#1e1e1e')
            
            # Update protocol distribution
            self.ax2.clear()
            if self.protocol_stats:
                protocols = list(self.protocol_stats.keys())[:5]  # Top 5 protocols
                counts = [self.protocol_stats[p] for p in protocols]
                colors = plt.cm.Set3(np.linspace(0, 1, len(protocols)))
                self.ax2.pie(counts, labels=protocols, colors=colors, autopct='%1.1f%%')
            self.ax2.set_title('Protocol Distribution', color='white', fontsize=12)
            
            # Update top talkers
            self.ax3.clear()
            if self.flows:
                top_flows = sorted(
                    self.flows.items(),
                    key=lambda x: x[1]['bytes'],
                    reverse=True
                )[:10]
                
                if top_flows:
                    labels = [f"{flow[0][0]}:{flow[0][1]}" for flow in top_flows]
                    values = [flow[1]['bytes'] for flow in top_flows]
                    
                    bars = self.ax3.bar(range(len(values)), values, color='skyblue')
                    self.ax3.set_xticks(range(len(labels)))
                    self.ax3.set_xticklabels(labels, rotation=45, ha='right')
                    
            self.ax3.set_title('Top Talkers (by Bytes)', color='white', fontsize=12)
            self.ax3.set_ylabel('Bytes', color='white')
            self.ax3.set_facecolor('#1e1e1e')
            
            # Update traffic timeline
            self.ax4.clear()
            if len(self.time_data) > 1:
                times = [t - self.time_data[0] for t in self.time_data]
                self.ax4.plot(times, list(self.byte_rate_data), 'r-', linewidth=2)
            self.ax4.set_title('Traffic Timeline', color='white', fontsize=12)
            self.ax4.set_ylabel('Bytes/sec', color='white')
            self.ax4.set_xlabel('Time (seconds)', color='white')
            self.ax4.set_facecolor('#1e1e1e')
            
            # Style all axes
            for ax in [self.ax1, self.ax2, self.ax3, self.ax4]:
                ax.tick_params(colors='white')
                for spine in ax.spines.values():
                    spine.set_color('white')
                    
            self.canvas.draw()
            
        except Exception as e:
            print(f"Visualization update error: {e}")
            
    def on_flow_select(self, event):
        """Handle flow selection in treeview"""
        try:
            selection = self.flows_tree.selection()
            if not selection:
                return
                
            item = self.flows_tree.item(selection[0])
            values = item['values']
            
            if values:
                details = f"""Flow Details:
Source: {values[0]}
Destination: {values[1]}
Protocol: {values[2]}
Packets: {values[3]:,}
Bytes: {values[4]:,}
Duration: {values[5]}

Flow established and active.
"""
                self.flow_details.delete('1.0', tk.END)
                self.flow_details.insert('1.0', details)
                
        except Exception as e:
            print(f"Flow selection error: {e}")
            
    def save_settings(self):
        """Save configuration settings"""
        try:
            self.config['capture_filter'] = self.filter_entry.get()
            self.config['max_packets'] = int(self.max_packets_entry.get())
            self.config['update_interval'] = float(self.interval_entry.get())
            self.config['alert_threshold'] = int(self.threshold_entry.get())
            
            messagebox.showinfo("Success", "Settings saved successfully!")
            
        except ValueError as e:
            messagebox.showerror("Error", f"Invalid setting value: {str(e)}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {str(e)}")
            
    def reset_settings(self):
        """Reset settings to defaults"""
        defaults = {
            'capture_filter': 'tcp or udp',
            'max_packets': 1000,
            'update_interval': 1.0,
            'alert_threshold': 100
        }
        
        self.filter_entry.delete(0, tk.END)
        self.filter_entry.insert(0, defaults['capture_filter'])
        
        self.max_packets_entry.delete(0, tk.END)
        self.max_packets_entry.insert(0, str(defaults['max_packets']))
        
        self.interval_entry.delete(0, tk.END)
        self.interval_entry.insert(0, str(defaults['update_interval']))
        
        self.threshold_entry.delete(0, tk.END)
        self.threshold_entry.insert(0, str(defaults['alert_threshold']))
        
        messagebox.showinfo("Success", "Settings reset to defaults!")
        
    def export_config(self):
        """Export configuration to file"""
        try:
            config_data = {
                'interface': self.selected_interface,
                'settings': self.config,
                'export_time': datetime.now().isoformat()
            }
            
            filename = f"network_monitor_config_{int(time.time())}.json"
            with open(filename, 'w') as f:
                json.dump(config_data, f, indent=2)
                
            messagebox.showinfo("Success", f"Configuration exported to {filename}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export config: {str(e)}")
            
    def run(self):
        """Start the application"""
        try:
            self.root.mainloop()
        except KeyboardInterrupt:
            self.stop_capture()
            self.root.quit()

def main():
    """Main function to run the network monitor"""
    try:
        # Check if running as root (required for packet capture)
        import os
        if os.geteuid() != 0:
            print("⚠️  Warning: This application requires root privileges for packet capture.")
            print("Please run with: sudo python network_monitor.py")
            
        app = NetworkMonitor()
        app.run()
        
    except Exception as e:
        print(f"Failed to start application: {e}")
        
    except KeyboardInterrupt:
        print("\nApplication terminated by user")

if __name__ == "__main__":
    main()
