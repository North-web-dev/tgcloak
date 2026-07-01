#include "td/mtproto/TlsInit.h"
#include "td/utils/port/SocketFd.h"
#include "td/utils/port/IPAddress.h"
#include "td/utils/buffer.h"
#include "td/net/TransparentProxy.h"
#include "td/actor/actor.h"
#include "td/actor/ConcurrentScheduler.h"
using namespace td;
int main(){
  ConcurrentScheduler sched(0,0);
  {
    auto guard=sched.get_main_guard();
    class Run final : public Actor {
      void start_up() final {
        class Cb final : public TransparentProxy::Callback {
         public:
          void set_result(Result<BufferedFd<SocketFd>>) final { Scheduler::instance()->finish(); }
          void on_connected() final {}
        };
        IPAddress ip; ip.init_ipv4_port("127.0.0.1",7000).ensure();
        auto sock=SocketFd::open(ip).move_as_ok();
        create_actor<mtproto::TlsInit>("Tls",std::move(sock),"www.google.com","0123456789abcdef",
          make_unique<Cb>(),ActorShared<>(),0.0).release();
      }
    };
    create_actor<Run>("Run").release();
  }
  sched.start(); while(sched.run_main(2)){} sched.finish(); return 0;
}
