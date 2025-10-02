#include "packetworker.h"
#include "devices/devices.h"
#include "filter/filter.h"
#include "protocols/proto_struct.h"

PacketWorker::PacketWorker(const QString &iface,
                           const QString &filter,
                           bool promisc)
  : m_iface(iface)
  , m_filter(filter)
  , m_promisc(promisc)
  , m_running(true)
  , m_netmask(0)
{}

PacketWorker::~PacketWorker() = default;

void PacketWorker::stop() {
    m_running.store(false, std::memory_order_relaxed);
}

void PacketWorker::process() {
    char errbuf[PCAP_ERRBUF_SIZE];

    // 1) open interface using Devices
    Devices dev;
    m_handle.reset(dev.init_packet_capture(
        m_iface.toStdString().c_str(),
        m_promisc
    ));
    if (!m_handle) {
        emit newPacket({}, {QStringLiteral("ERROR: %1").arg(dev.error_buffer)});
        return;
    }

    Sniffing::setLinkLayer(pcap_datalink(m_handle.get()));

    // 2) compile & set filter via Filters
    Filters flt;
    flt.netmask_lookup(m_iface.toStdString(), errbuf);
    m_netmask = flt.get_mask();
    flt.filter_processing(
        m_handle.get(),
        m_filter.toStdString().c_str(),
        0,
        m_netmask
    );

    // 3) capture loop
    while (m_running.load(std::memory_order_relaxed)) {
        int ret = pcap_dispatch(
            m_handle.get(),
            -1,
            Sniffing::packet_callback,   
            reinterpret_cast<u_char*>(this)
        );
        if (ret == PCAP_ERROR_BREAK)
            break;
        if (ret < 0) {
            qWarning("pcap_dispatch error: %s", pcap_geterr(m_handle.get()));
            break;
        }
    }
    m_handle.reset();
}

void PacketWorker::updateFilter(const QString &filter) {
    m_filter = filter;
    if (!m_handle) return;

    Filters flt;
    char errbuf[PCAP_ERRBUF_SIZE];
    flt.netmask_lookup(m_iface.toStdString(), errbuf);
    m_netmask = flt.get_mask();
    flt.filter_processing(
        m_handle.get(),
        m_filter.toStdString().c_str(),
        0,
        m_netmask
    );
}
