import time
import random
import concurrent.futures
from scapy.all import IP, sr1, TCP, sr

# 開始時間のタイマー
start_timer = time.perf_counter()
print('スキャン開始...')

# host = テスト対象、src_port = テスト者（ランダムポート）、ports = list(テスト範囲)
host = "5e3914f3.mbsdcc2021.net"
src_port = random.randint(1025,65534)
ports = list(range(1,65536))
print("スキャン対象：{} , スキャン範囲：{} ~ {}".format(host,ports[0],ports[-1]))

# 精度調整/デバグ用
open_port_counter = 0

# ポートスキャン関数
def port_scan(dst_port):
# テスト者からSYNフラグを転送、timeout = wait_timeはテスト精度のため、wait_time = 1秒（暫定）に設定する
    wait_time = 1
    resp = sr1(
        IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags="S"),timeout=wait_time,
        verbose=0,
    )
    # レスポンスがない場合
    if resp is None:
        # return f"{host}:{dst_port} is filtered (silently dropped)."
        return ''
    # レスポンスありかつテスト対象が受信済みフラグを返す場合
    elif(resp.haslayer(TCP)):
        if(resp.getlayer(TCP).flags == 0x12):
            # 通信中断のため、テスト者がRSTフラグを転送、ポートが開放していることを確認
            send_rst = sr(
                IP(dst=host)/TCP(sport=src_port,dport=dst_port,flags='R'),
                timeout=wait_time,
                verbose=0,
            )
            # 精度調整/デバグ用
            global open_port_counter
            open_port_counter = open_port_counter + 1
            # return f"{host}:{dst_port} is open."
            return f"{host}:{dst_port} が開放されています\n"

        # テスト対象から受信を拒否するフラグを受け、ポートが開放していないことを確認
        elif (resp.getlayer(TCP).flags == 0x14):
            # return f"{host}:{dst_port} is closed."
            return ''


# Thread 処理開始
with concurrent.futures.ThreadPoolExecutor() as executor:
    results = executor.map(port_scan, ports)
    for result in results:
        print(result , end = '')

# 終了時間のタイマー
finish_timer = time.perf_counter()

# 精度調整/デバグ用
print(f'合計： {open_port_counter} 個、開放されているポートがを検出しました')

# 処理時間の計算とプリント
print(f'スキャン終了、処理時間： {round(finish_timer-start_timer,2)} 秒')