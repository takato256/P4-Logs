#!/usr/bin/env python3

import socket
import sys
from time import sleep

from scapy.all import (
    IP,
    UDP,
    Ether,
    Dot1Q,
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    PacketListField,
    ShortField,
    get_if_hwaddr,
    get_if_list,
    sendp
)
from scapy.layers.inet import _IPOption_HDR

# 利用可能なネットワークインターフェースから "eth0" を探し、その名前を返す関数
def get_if():
    ifs = get_if_list()  # 利用可能なインターフェースのリストを取得
    iface = None         # インターフェース名を保存する変数
    for i in get_if_list():
        if "eth0" in i:  # インターフェース名に "eth0" を含む場合
            iface = i
            break
    if not iface:  # "eth0" が見つからなかった場合のエラーメッセージ
        print("Cannot find eth0 interface")
        exit(1)
    return iface  # 見つかったインターフェース名を返す

# SwitchTrace パケットクラスの定義
class SwitchTrace(Packet):
    fields_desc = [
        IntField("swid", 0),     # スイッチ ID フィールド (デフォルトは 0)
        IntField("qdepth", 0)    # キュー深さ (queue depth) フィールド (デフォルトは 0)
    ]
    def extract_padding(self, p):
        return "", p  # パディングを無視して処理するメソッド

# IPオプションにMRI (Multi Router Information)を追加するクラス
class IPOption_MRI(IPOption):
    name = "MRI"        # オプションの名前
    option = 31         # オプション番号 (IPオプションフィールドの番号)
    fields_desc = [
        _IPOption_HDR,  # IPオプションの標準ヘッダー
        FieldLenField(
            "length", None, fmt="B",
            length_of="swtraces",          # swtracesの長さに基づきlengthフィールドを設定
            adjust=lambda pkt, l: l * 2 + 4  # パケットの長さに応じた調整
        ),
        ShortField("count", 0),           # swtraces のエントリ数
        PacketListField(
            "swtraces", [],               # swtraces フィールドに SwitchTrace のリストを格納
            SwitchTrace,
            count_from=lambda pkt: (pkt.count * 1)  # count フィールドの数に基づく
        )
    ]

# メイン関数
def main():
    # コマンドライン引数の数を確認
    if len(sys.argv) < 3:
        print('pass 2 arguments: <destination> "<message>"')  # 引数が不足している場合のエラー
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])  # 宛先のIPアドレスを取得
    iface = get_if()                          # 使用するインターフェースを取得

    # 送信するEther/IP/UDPパケットの作成
    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=1) / IP(
        dst=addr, options=IPOption_MRI(count=0,  # swtracesフィールドが空のMRIオプション
            swtraces=[])) / UDP(
            dport=4321, sport=1234) / sys.argv[2]  # UDPの宛先ポートと送信ポートを設定

    # サンプルとして swtraces を含むパケットの構成 (コメントアウト)
    # pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
    #     dst=addr, options=IPOption_MRI(count=2,
    #         swtraces=[SwitchTrace(swid=0, qdepth=0), SwitchTrace(swid=1, qdepth=0)]
    #     )) / UDP(dport=4321, sport=1234) / sys.argv[2]

    pkt.show2()  # パケット構造を表示
    # hexdump(pkt)  # パケットを16進数で表示 (コメントアウト)

    # パケット送信ループ
    try:
        for i in range(int(sys.argv[3])):  # 第3引数で指定された回数だけ送信
            sendp(pkt, iface=iface)         # インターフェースからパケットを送信
            sleep(1)                        # 1秒の待機
    except KeyboardInterrupt:               # Ctrl+Cで終了
        raise

# スクリプトが直接実行された場合にmain()を呼び出し
if __name__ == '__main__':
    main()

