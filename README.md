# 스마트 네트워크 서비스 AD과제

팀14
학번:20213051 이름:이재준
학번:20213049 이름:이재영


---

# ▶️ 실행 방법

터미널을 먼저 실행시킨 뒤 smart_net_suite_skeleton.py가 있는 위치로 이동한 후
## 📍 macOS/unix
```bash
python3 smart_net_suite_skeleton.py
```
## 📍 Window
```bash
python smart_net_suite_skeleton.py
```
# 📊 16개 요구사항 체크리스트

| 번호 | 요구사항 | 상태 |
|------|-----------|-------|
| 1 | IP 구성 확인 | ✔️ |
| 2 | 바이트 정렬 hton/ntoh | ✔️ |
| 3 | IP 변환 pton/ntop | ✔️ |
| 4 | DNS/역방향 조회 | ✔️ |
| 5 | 포트 검사 | ✔️ |
| 6 | netstat 필터 | ✔️ |
| 7 | TCP 서버 상태 표시 | ✔️ |
| 8 | TCP 클라이언트 | ✔️ |
| 9 | 소켓 버퍼 조회 | ✔️ |
| 10 | 네트워크 그림판 | ✔️ |
| 11 | FIXED 전송 | ✔️ |
| 12 | VAR 전송 | ✔️ |
| 13 | MIX 전송 | ✔️ |
| 14 | 전송 후 종료 | ✔️ |
| 15 | Lock(임계영역) | ✔️ |
| 16 | Event(안전 종료) | ✔️ |

# 1. IP 구성 확인

## 실행결과
<img width="1432" height="753" alt="스크린샷 2025-12-10 오전 10 09 11" src="https://github.com/user-attachments/assets/15e8bc71-ca74-4e33-a99c-fca5226ec0c7" />
터미널에서 ifconfig -a 명령을 실행했을 때와 비교해보면 ip 구성 확인을 눌렀을 때 결과가 같은 것을 확인할 수 있다.

## do_ipconfig
```bash
    def do_ipconfig(self):
        pc_os = self.pc_os
        command = "ifconfig -a"

        if (pc_os == "Windows"): command = "ipconfig /all"

        pipe = os.popen(command)
        output = pipe.read()
        pipe.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        self._append(target, f"$ {command}\n{output}")
```
사용자 os를 먼저 인식한 뒤 os에 맞게 IP 구성을 확인하는 명령을 실행시켜준다.

# 2. 바이트 정렬 함수

## 실행결과
<img width="572" height="110" alt="스크린샷 2025-12-10 오전 10 20 20" src="https://github.com/user-attachments/assets/4925baf3-3c11-4995-8275-9c038914f751" />

네트워크 진단 탭에서 바이트/주소 변환의 hton/ntoh 데모를 클릭한 결과이다
16비트, 32비트, 64비트에서 변환/역변환이 올바르게 일어나고 있는 것을 눈으로 확인할 수 있다

## do_hton
```bash
    def do_hton(self):
        self._append(self.out_diag, "---------[hton/ntoh 데모]---------")

        # 16 비트
        v16 = 0x1234
        net16 = socket.htons(v16)
        host16 = socket.ntohs(net16)
        self._append(self.out_diag, f"16bit host=0x{v16:04X} -> network=0x{net16:04X} -> host=0x{host16:04X}")

        # 32비트
        v32 = 0x12345678
        net32 = socket.htonl(v32)
        host32 = socket.ntohl(net32)
        self._append(self.out_diag, f"32bit host=0x{v32:08X} -> network=0x{net32:08X} -> host=0x{host32:08X}")

        # 64비트 (struct 이용)
        v64 = 0x0123456789ABCDEF

        host_bytes = struct.pack("=Q", v64)
        net_bytes = struct.pack("!Q", v64)

        swapped = int.from_bytes(net_bytes, byteorder='little')

        self._append(self.out_diag, f"64bit host=0x{v64:016X}")
        self._append(self.out_diag, f"      host bytes (native endian)     = {host_bytes.hex()}")
        self._append(self.out_diag, f"      network bytes (big-endian)     = {net_bytes.hex()}")
        self._append(self.out_diag, f"      network->little endian swap    = 0x{swapped:016X}")
        self._append(self.out_diag, "-------------------------------------")
```
16비트에서는 socket.htons, socket.ntohs
32비트에서는 socket.htonl, socket.ntohl
64비트에서는 struct를 이용하여 다음과 같은 실행화면이 나올 수 있게 하였다

# 3. IP 변환 pton/ntop

## IPv4/IPv6실행결과
<img width="573" height="211" alt="스크린샷 2025-12-10 오전 10 59 07" src="https://github.com/user-attachments/assets/ad9d3efd-f37b-4197-b9bd-51fca5a6b770" />

8.8.8.8과 6.6.6.6에 대한 pton/ntop가 잘 이루어진 것을 확인할 수 있습니다.

2001:4860:4860::8888과 1001:1001:1001::1001에 대한 pton/ntop 변환이 잘 이루어진 것을 확인할 수 있습니다.
다만 2001:4860:4860::8888 pton 앞부분에서 H와 같이 문자로 나타는 것은
바이트 값 자체가 문자로 표현될 수 있으면 Python은 그걸 repr에 포함해서 보기 조금 이상한 형태가 되는 것입니다.

## do_inet4/do_inet6
```bash
    def do_inet4(self):
        demo_ipv4 = self.var_ipv4.get()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)

        self._append(target, "---------IPv4 (AF_INET)---------")
        ipv4_bin = socket.inet_pton(socket.AF_INET, demo_ipv4)
        self._append(target, f"pton : {ipv4_bin!r}")

        ipv4_str_converted = socket.inet_ntop(socket.AF_INET, ipv4_bin)
        self._append(target, f"ntop : '{ipv4_str_converted}'")
        self._append(target, "--------------------------------")

    def do_inet6(self):
        demo_ipv6 = self.var_ipv6.get()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)

        self._append(target, "---------IPv6 (AF_INET6)---------")
        ipv6_bin = socket.inet_pton(socket.AF_INET6, demo_ipv6)
        self._append(target, f"pton : {ipv6_bin!r}")

        ipv6_str_converted = socket.inet_ntop(socket.AF_INET6, ipv6_bin)
        self._append(target, f"ntop : '{ipv6_str_converted}'")
        self._append(target, "--------------------------------")
```
ipv4와 ipv6에 해당하는 문자열을 가져와서 inet_pton / inet_ntop를 이용하여 출력했습니다

# 4. DNS/역방향 조회

## DNS/역방향 실행결과
<img width="1361" height="751" alt="스크린샷 2025-12-10 오전 11 11 19" src="https://github.com/user-attachments/assets/c975c079-7c5b-4a23-a0d3-631d82b4ee62" />

example.com과 8.8.8.8에 대한 DNS/역방향 버튼을 클릭했을 때의 결과와 터미널에서 nslookup을 통해 조회한 두 항목에 대한 결과가 같음을 통해 잘 실행되는 것을 확인할 수 있다.

## do_dns/do_reverse
```bash
    def do_dns(self):
        hostname = self.var_dns.get()
        command = f'nslookup {hostname}'

        pipe = os.popen(command)
        output = pipe.read()
        pipe.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        self._append(target, f"$ {command}\n{output}")

    def do_reverse(self):
        hostname = self.var_rev.get()
        command = f'nslookup {hostname}'

        pipe = os.popen(command)
        output = pipe.read()
        pipe.close()

        target = {"diag": self.out_diag, "sfc": self.out_sfc}.get("diag", None)
        self._append(target, f"$ {command}\n{output}")
```
nslookup에 대한 동작은 OS마다 동일하여 따로 나눠줄 필요없고 GUI 입력값을 불러와 터미널에서 실행시킨 값을 가져오는 형태로 작성하였습니다.


