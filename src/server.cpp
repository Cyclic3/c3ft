#include <boost/asio/ip/udp.hpp>

#include <array>
#include <numeric>
#include <optional>
#include <span>
#include <variant>
#include <iostream>

static std::array<std::pair<std::string_view, std::string_view>, 1> stun_eps {
  {{ "stun.l.google.com", "19302" }}
};

namespace c3ft {
  class stun_packet {
  private:
    static constexpr std::array<uint8_t, 4> magic_cookie{0x21, 0x12, 0xa4, 0x42};

  public:
    enum message_type : uint16_t {
      Request = 0,
      Indication = 0x10,
      Success = 0x100,
      Error = 0x110,

      Binding = 0x1

    };
    enum attribute_type : uint16_t {
      MappedAddress = 0x0000,
      XorMappedAddress = 0x0020,

      ATTR_TYPE_MASK = 0x0fff
    };

    struct attributes {
      class mapped_address {
        friend stun_packet;
      public:
        boost::asio::ip::udp::endpoint ep;

      private:
        inline void serialise_to(std::vector<uint8_t>& vec, std::span<uint8_t, 12>) {
          // Type
          vec.push_back(MappedAddress >> 8);
          vec.push_back(MappedAddress & 0xff);
          if (ep.protocol() == boost::asio::ip::udp::v4()) {
            // Size
            vec.push_back(0); vec.push_back(8);
            // Family
            vec.push_back(0); vec.push_back(1);
            // Port
            vec.push_back(ep.port() >> 8);
            vec.push_back(ep.port() & 0xff);
            // Address
            auto addr = ep.address().to_v4().to_bytes();
            std::copy(addr.begin(), addr.end(), std::back_inserter(vec));
          }
          else {
            // Size
            vec.push_back(0); vec.push_back(20);
            // Family
            vec.push_back(0); vec.push_back(2);
            // Port
            vec.push_back(ep.port() >> 8);
            vec.push_back(ep.port() & 0xff);
            // Address
            auto addr = ep.address().to_v6().to_bytes();
            std::copy(addr.begin(), addr.end(), std::back_inserter(vec));
          }
        }

        inline static mapped_address deserialise(std::span<uint8_t> dat, std::span<uint8_t, 12>) {
          if ((dat[0] << 8 | dat[1]) == 1) {
            if (dat.size() != 8)
              throw std::invalid_argument{"Attribute malformed"};
            auto* addr_bytes = reinterpret_cast<boost::asio::ip::address_v4::bytes_type*>(dat.data() + 4);
            return {{boost::asio::ip::address_v4(*addr_bytes), static_cast<uint16_t>(dat[2] << 8 | dat[3])}};
          }
          else if ((dat[0] << 8 | dat[1]) == 2) {
            if (dat.size() != 20)
              throw std::invalid_argument{"Attribute malformed"};
            auto* addr_bytes = reinterpret_cast<boost::asio::ip::address_v6::bytes_type*>(dat.data() + 4);
            return {{boost::asio::ip::address_v6(*addr_bytes), static_cast<uint16_t>(dat[2] << 8 | dat[3])}};
          }
          else
            throw std::invalid_argument{"Unknown protocol family"};
        }
      };
      class xor_mapped_address {
        friend stun_packet;
      public:
        boost::asio::ip::udp::endpoint ep;

      private:
        inline void serialise_to(std::vector<uint8_t>& vec, std::span<uint8_t, 12> id) {
          // Type
          vec.push_back(XorMappedAddress >> 8);
          vec.push_back(XorMappedAddress & 0xff);
          if (ep.protocol() == boost::asio::ip::udp::v4()) {
            // Size
            vec.push_back(0); vec.push_back(8);
            // Family
            vec.push_back(0); vec.push_back(1);
            // Port
            vec.push_back((ep.port() >> 8) ^ magic_cookie[0]);
            vec.push_back((ep.port() & 0xff) ^ magic_cookie[1]);
            // Address
            auto addr = ep.address().to_v4().to_bytes();
            std::transform(addr.begin(), addr.end(), magic_cookie.begin(), addr.begin(), std::bit_xor<uint8_t>{});
            std::copy(addr.begin(), addr.end(), std::back_inserter(vec));
          }
          else {
            // Size
            vec.push_back(0); vec.push_back(20);
            // Family
            vec.push_back(0); vec.push_back(2);
            // Port
            vec.push_back((ep.port() >> 8) ^ magic_cookie[0]);
            vec.push_back((ep.port() & 0xff) ^ magic_cookie[1]);
            // Address
            auto addr = ep.address().to_v6().to_bytes();
            std::transform(addr.begin(), addr.begin() + 4, magic_cookie.begin(), addr.begin(), std::bit_xor<uint8_t>{});
            std::transform(addr.begin() + 4, addr.end(), id.begin(), addr.begin() + 4, std::bit_xor<uint8_t>{});
            std::copy(addr.begin(), addr.end(), std::back_inserter(vec));
          }
        }
        inline static xor_mapped_address deserialise(std::span<uint8_t> dat, std::span<uint8_t, 12> id) {
          uint16_t port = ((dat[2] ^ magic_cookie[0]) << 8) | (dat[3] ^ magic_cookie[1]);
          if ((dat[0] << 8 | dat[1]) == 1) {
            if (dat.size() != 8)
              throw std::invalid_argument{"Attribute malformed"};
            auto addr = *reinterpret_cast<boost::asio::ip::address_v4::bytes_type*>(dat.data() + 4);
            std::transform(addr.begin(), addr.end(), magic_cookie.begin(), addr.begin(), std::bit_xor<uint8_t>{});
            return {{boost::asio::ip::address_v4(addr), port}};
          }
          else if ((dat[0] << 8 | dat[1]) == 2) {
            if (dat.size() != 20)
              throw std::invalid_argument{"Attribute malformed"};
            auto addr = *reinterpret_cast<boost::asio::ip::address_v4::bytes_type*>(dat.data() + 4);
            std::transform(addr.begin(), addr.begin() + 4, magic_cookie.begin(), addr.begin(), std::bit_xor<uint8_t>{});
            std::transform(addr.begin() + 4, addr.end(), id.begin(), addr.begin() + 4, std::bit_xor<uint8_t>{});
            return {{boost::asio::ip::address_v4(addr), port}};
          }
          else
            throw std::invalid_argument{"Unknown protocol family"};
        }
      };
    };

    using attribute = std::variant<attributes::mapped_address, attributes::xor_mapped_address>;

  private:
    message_type _type = static_cast<message_type>(Binding | Request);
    std::vector<attribute> _attribs;

  public:
    std::optional<boost::asio::ip::udp::endpoint> try_get_mapped_address() {
      for (auto& i : _attribs) {
        auto res = std::visit([](auto& x) {
          using T = std::decay_t<decltype(x)>;
          if constexpr (std::is_same_v<T, attributes::mapped_address> || std::is_same_v<T, attributes::xor_mapped_address>)
            return std::optional{x.ep};
          else
            return std::nullopt;
        }, i);
        if (res)
          return res;
      }
      return std::nullopt;
    }

  public:
    std::vector<uint8_t> serialise(std::span<uint8_t, 12> const& id) {
      std::vector<uint8_t> ret(20);
      // type
      ret[0] = static_cast<uint16_t>(_type) >> 8;
      ret[1] = static_cast<uint16_t>(_type) & 0xff;

      // size (to be filled later)
      // ret[2] = ?; ret[3] = ?;

      // Magic cookie
      std::copy(magic_cookie.begin(), magic_cookie.end(), ret.begin() + 4);

      // Transaction id
      std::copy(id.begin(), id.end(), ret.begin() + 8);

      for (auto& attrib : _attribs)
        std::visit([&](auto& x) { x.serialise_to(ret, id);}, attrib);

      // Finish the size field
      auto extra_size = ret.size() - 20;
      ret[2] = extra_size >> 8;
      ret[3] = extra_size & 0xff;

      return ret;
    }

    static inline std::pair<stun_packet, std::span<uint8_t, 12>> deserialise(std::span<uint8_t> dat) {
      if (dat.size() < 20)
        throw std::invalid_argument{"STUN packet too small for header"};
      stun_packet ret;
      ret._type = static_cast<message_type>(dat[0] << 8 | dat[1]);
      const size_t len = dat[2] << 8 | dat[3] + 20;
      auto id = dat.subspan<8, 12>();
      // FIXME: cba to check magic cookie and other bs

      size_t current_len;
      for (size_t offset = 20; offset < len; offset += current_len + 4) {
        current_len = (dat[offset + 2] << 8 | dat[offset + 3]);
        if (offset + current_len > len)
          throw std::invalid_argument{"STUN packet truncated"};
        switch ((dat[offset] <<8 | dat[offset + 1]) & ATTR_TYPE_MASK) {
          case MappedAddress:
            ret._attribs.emplace_back(attributes::mapped_address::deserialise(dat.subspan(offset + 4, current_len), id));
            break;
          case XorMappedAddress:
            ret._attribs.emplace_back(attributes::xor_mapped_address::deserialise(dat.subspan(offset + 4, current_len), id));
            break;
          default:
            throw std::invalid_argument{"Unknown attribute type"};
        }
      }

      return {std::move(ret), id};
    }
  };

  auto make_buffer(std::span<const uint8_t> buf) {
    return boost::asio::buffer(buf.data(), buf.size());
  }
  auto make_mut_buffer(std::span<uint8_t> buf) {
    return boost::asio::mutable_buffer(buf.data(), buf.size());
  }

  static std::optional<boost::asio::ip::udp::endpoint> do_stun(boost::asio::ip::udp::socket& sock) {
    stun_packet stun_req;

    std::vector<uint8_t> buf(65536);
    boost::asio::ip::udp::resolver resolver{sock.get_executor()};
    for (auto [host, port] : stun_eps) {
      auto x = resolver.resolve(host, port);
      for (auto& ep: resolver.resolve(host, port)) {
        boost::system::error_code err;
        std::array<uint8_t, 12> id = {0};
        sock.send_to(make_buffer(stun_req.serialise(id)), ep.endpoint(), {}, err);
        auto x = err.message();
        if (err)
          continue;

        auto recv_buf = boost::asio::buffer(buf);

        boost::asio::ip::udp::endpoint recv_ep;
        // TODO: timeout
        auto n_recv = sock.receive_from(recv_buf, recv_ep);

        // TODO: find a non-abusable way of handling this
        if (recv_ep != ep)
          continue;

        auto [recv_packet, recv_id] = stun_packet::deserialise(std::span(buf.data(), n_recv));

        // TODO: find a non-abusable way of handling this
        if (!std::equal(id.begin(), id.end(), recv_id.begin()))
          continue;

        if (auto our_ep = recv_packet.try_get_mapped_address())
          return our_ep;
      }
    }

    return {};
  }

  void test() {
    boost::asio::io_context io_ctx;
    boost::asio::ip::udp::socket sock{io_ctx, {boost::asio::ip::address_v4::any(), 0}};
    auto res = do_stun(sock);
    std::cout << res.value() << std::endl;
    res = do_stun(sock);
    std::cout << res.value() << std::endl;

    std::string addr_str; uint16_t port;
    std::cin >> addr_str >> port;
    boost::asio::ip::udp::endpoint remote_ep{boost::asio::ip::address::from_string(addr_str), port};

    sock.connect(remote_ep);
//    sock.connect(res.value());
//    sock.connect({boost::asio::ip::address::from_string("134.122.100.97"), 6969});

    boost::asio::const_buffer msg("hello, world", 12);
    sock.send(msg);

    std::vector<uint8_t> buf(64, 0);
    size_t n = sock.receive(make_mut_buffer(buf));
    std::cout << n << ": " << std::string_view(reinterpret_cast<char const*>(buf.data()), n) << std::endl;
  }
}
