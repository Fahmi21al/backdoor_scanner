# System Forensic Scanner (SFS)

[English](#english) | [Indonesia](#indonesia)

---

<a id="english"></a>
## 🇬🇧 English

System Forensic Scanner (SFS) is a digital forensic and incident response platform designed to investigate web applications suspected of security compromises. It operates strictly in **read-only** mode without modifying target files, ensuring forensic integrity.

### Features
- **Core File Forensics**: Detects modified files, unauthorized additional files, malware/webshells, and Indicators of Compromise (IOC) by comparing source code with clean baselines.
- **Malware & Webshell Detection**: Integrates YARA rules and IOC regex scanning to identify backdoors, webshells, and malicious payloads.
- **Attack Surface Discovery**: Utilizes specialized tools like Katana and Httpx to discover exposed endpoints and profile the technology stack.
- **Vulnerability Assessment**: Runs Nuclei templates to discover CVEs and misconfigurations in the target application.
- **Database Forensics**: Parses and analyzes `.sql` and `.sql.gz` dumps to detect new administrator accounts or suspicious roles.
- **Timeline Reconstruction**: Reconstructs events sequentially from filesystem changes, access logs, and database events.
- **Risk Scoring Engine**: Calculates an overall risk score using defined weights based on findings.
- **Comprehensive Reporting**: Generates detailed reports in JSON, HTML, and PDF formats for further analysis.

### Supported Target Applications
- Open Journal Systems (OJS)
- WordPress
- Laravel
- Moodle
- Generic PHP Applications

### Tech Stack
- **Backend Language**: Golang 1.25+
- **Database**: PostgreSQL 17+
- **Frontend UI**: HTML, CSS, JavaScript (Vanilla)
- **Engines & Tools**:
  - `go-yara/v4` for YARA rule matching
  - `go-difflib` for generating unified diffs
  - [Nuclei](https://github.com/projectdiscovery/nuclei) for vulnerability scanning
  - [Katana](https://github.com/projectdiscovery/katana) for crawling and attack surface discovery
  - [Httpx](https://github.com/projectdiscovery/httpx) for HTTP probing

### Getting Started

#### Prerequisites
- Go 1.25 or higher
- PostgreSQL 17 or higher
- Make sure Nuclei, Katana, and Httpx are installed and accessible in your system's PATH.

#### Setup Instructions
1. **Clone the Repository**
   ```bash
   git clone https://github.com/Fahmi21al/backdoor_scanner.git
   cd backdoor_scanner/sfs
   ```

2. **Install Dependencies**
   Run the following command to download and install all required Go modules:
   ```bash
   go mod tidy
   ```

3. **Configure the Database**
   - Create a PostgreSQL database for SFS.
   - Update your connection settings as required by the application configuration.

4. **Run the Application**
   ```bash
   go run cmd/api/main.go
   ```

5. **Access the Web Interface**
   Open your browser and navigate to the application web interface.

### Architecture
SFS uses a **Modular Monolith** architecture, consisting of specialized engines: Baseline, Hash, Diff, YARA, IOC, Katana, Httpx, Nuclei, Audit, Database Forensic, Timeline, Risk, and Reporting. 

### Development Roadmap
- Live Database Connections
- Multi-User and API Authentication
- Cluster / Distributed Scanning
- SIEM / SOC / EDR Integration
- Real-time continuous monitoring (Agent Mode)

---

<a id="indonesia"></a>
## 🇮🇩 Indonesia

System Forensic Scanner (SFS) adalah platform forensik digital dan respons insiden (IR) yang dirancang untuk menyelidiki aplikasi web yang dicurigai mengalami kompromi keamanan. Aplikasi ini beroperasi sepenuhnya dalam mode **read-only** tanpa memodifikasi file target, sehingga menjaga integritas bukti forensik.

### Fitur
- **Core File Forensics**: Mendeteksi file yang dimodifikasi, file tambahan tak dikenal, malware/webshell, dan Indicators of Compromise (IOC) dengan membandingkan *source code* terhadap *baseline* (sumber asli) yang bersih.
- **Deteksi Malware & Webshell**: Mengintegrasikan YARA rules dan pemindaian regex IOC untuk mengidentifikasi *backdoor*, *webshell*, dan muatan berbahaya lainnya.
- **Attack Surface Discovery**: Menggunakan *tools* khusus seperti Katana dan Httpx untuk menemukan *endpoint* yang terekspos serta melakukan profil pada tumpukan teknologi (Tech Stack).
- **Penilaian Kerentanan (Vulnerability Assessment)**: Menjalankan *template* Nuclei untuk menemukan kerentanan (CVE) dan miskonfigurasi pada aplikasi target.
- **Database Forensics**: Membaca dan menganalisis file *dump* `.sql` dan `.sql.gz` untuk mendeteksi penambahan akun administrator baru atau peran yang mencurigakan.
- **Rekonstruksi Timeline**: Menyusun ulang kejadian secara kronologis mulai dari perubahan *filesystem*, *access logs*, dan *event* pada database.
- **Risk Scoring Engine**: Menghitung skor risiko (Risk Score) secara keseluruhan menggunakan bobot yang telah ditentukan berdasarkan temuan.
- **Pelaporan Komprehensif**: Menghasilkan laporan terperinci dalam format JSON, HTML, dan PDF untuk analisis lebih lanjut.

### Aplikasi Target yang Didukung
- Open Journal Systems (OJS)
- WordPress
- Laravel
- Moodle
- Aplikasi PHP Generik

### Tech Stack (Teknologi yang Digunakan)
- **Bahasa Backend**: Golang 1.25+
- **Database**: PostgreSQL 17+
- **Frontend UI**: HTML, CSS, JavaScript (Vanilla)
- **Engine & Tools Tambahan**:
  - `go-yara/v4` untuk pencocokan aturan YARA
  - `go-difflib` untuk membuat perbedaan baris kode (*unified diffs*)
  - [Nuclei](https://github.com/projectdiscovery/nuclei) untuk pemindaian kerentanan
  - [Katana](https://github.com/projectdiscovery/katana) untuk pencarian *attack surface*
  - [Httpx](https://github.com/projectdiscovery/httpx) untuk *HTTP probing*

### Panduan Memulai (Getting Started)

#### Prasyarat
- Go versi 1.25 atau lebih tinggi
- PostgreSQL versi 17 atau lebih tinggi
- Pastikan Nuclei, Katana, dan Httpx telah terinstal dan terdaftar di PATH sistem Anda.

#### Langkah Instalasi
1. **Clone Repository**
   ```bash
   git clone https://github.com/Fahmi21al/backdoor_scanner.git
   cd backdoor_scanner/sfs
   ```

2. **Install Dependencies**
   Jalankan perintah berikut untuk mengunduh dan menginstal semua modul Go yang dibutuhkan:
   ```bash
   go mod tidy
   ```

3. **Konfigurasi Database**
   - Buat database baru di PostgreSQL khusus untuk SFS.
   - Sesuaikan *connection string* sesuai dengan konfigurasi aplikasi Anda.

4. **Jalankan Aplikasi**
   ```bash
   go run cmd/api/main.go
   ```

5. **Akses Antarmuka Web**
   Buka *browser* Anda dan kunjungi halaman antarmuka web SFS untuk mulai menggunakan.

### Arsitektur
SFS menggunakan arsitektur **Modular Monolith**, yang terdiri dari beberapa spesialisasi *engine*: Baseline, Hash, Diff, YARA, IOC, Katana, Httpx, Nuclei, Audit, Database Forensic, Timeline, Risk, dan Reporting.

### Peta Jalan Pengembangan (Roadmap)
- Koneksi Database secara langsung (*Live DB Connections*)
- Multi-User dan Autentikasi API
- Pemindaian Terdistribusi / Cluster
- Integrasi ke SIEM / SOC / EDR
- Pemantauan berkelanjutan *Real-time* (*Agent Mode*)
