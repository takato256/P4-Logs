#!/usr/bin/env python3
import sys

from scapy.all import (
    FieldLenField,
    IntField,
    IPOption,
    Packet,
    PacketListField,
    ShortField,
    get_if_list,
    sniff
)
from scapy.layers.inet import _IPOption_HDR

# 利用可能なネットワークインターフェースのうち、"eth0" を検索して返す関数
def get_if():
    ifs = get_if_list()  # インターフェースのリストを取得
    iface = None
    for i in get_if_list():
        if "eth0" in i:  # インターフェース名が "eth0" の場合
            iface = i
            break
    if not iface:  # "eth0" が見つからない場合、エラーメッセージを表示
        print("Cannot find eth0 interface")
        exit(1)
    return iface  # 見つかったインターフェース名を返す

# SwitchTraceパケットクラスの定義
class SwitchTrace(Packet):
    fields_desc = [
        IntField("swid", 0),     # スイッチIDフィールド (デフォルトは0)
        IntField("qdepth", 0)    # キューの深さ (デフォルトは0)
    ]
    def extract_padding(self, p):
        return "", p  # パディングの抽出を無視するメソッド

# IPオプションにMRI (Multi Router Information) を追加するクラス
class IPOption_MRI(IPOption):
    name = "MRI"  # オプションの名前
    option = 31   # オプションの番号（IPオプションフィールド番号）

    fields_desc = [
        _IPOption_HDR,  # IPオプションの標準ヘッダー
        FieldLenField(
            "length", None, fmt="B",
            length_of="swtraces",
            adjust=lambda pkt, l: l * 2 + 4  # swtracesリストの長さに基づいて長さを設定
        ),
        ShortField("count", 0),  # swtracesのエントリ数
        PacketListField(
            "swtraces",      # swtracesフィールドにSwitchTraceのリストを格納
            [],
            SwitchTrace,
            count_from=lambda pkt: (pkt.count * 1)  # countの値に基づいてSwitchTrace数を指定
        )
    ]

# パケットを受信したときに呼び出される関数
def handle_pkt(pkt):
    print("got a packet")  # パケット受信メッセージ
    pkt.show2()            # パケットの詳細を表示
    # hexdump(pkt)         # パケットの16進ダンプを表示（コメントアウト）
    sys.stdout.flush()     # 出力を即時フラッシュして表示

# メイン関数
def main():
    iface = 'eth0'  # スニッフィングするインターフェース（eth0）
    print("sniffing on %s" % iface)  # スニッフィング開始メッセージ
    sys.stdout.flush()  # 出力をフラッシュ
    sniff(
        filter="udp and port 4321",  # UDPパケットでポート4321をフィルタリング
        iface=iface,                 # 使用するインターフェース
        prn=lambda x: handle_pkt(x)  # パケット受信時にhandle_pktを呼び出す
    )

# スクリプトが直接実行された場合にmain()を呼び出し
if __name__ == '__main__':
    main()
