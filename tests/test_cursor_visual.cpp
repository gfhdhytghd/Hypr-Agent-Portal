#include "plugin/cursor_visual.hpp"
#include <cassert>
#include <iostream>
#include <limits>
using namespace CursorVisual;
int main() {
    Settings s;
    assert(validSession("mcp_A-1"));
    for (const auto& id : {"", "../x", "a,b", "a b", "a=x", "é"}) assert(!validSession(id));
    assert(!validSession(std::string(65,'a')));
    std::vector<std::string> args{"window","1","2","click","left"};
    std::string session;
    assert(takeSession(args,session) && session=="legacy" && args.size()==5);
    args.push_back("cursor_session=mcp-123");
    assert(takeSession(args,session) && session=="mcp-123" && args.size()==5);
    args.push_back("cursor_session=bad,value");
    assert(!takeSession(args,session) && args.size()==6);
    args={"window","1","2","move","cursor_session=mcp-a","theme=minimal","reduced_motion=1","motion_ms=250"};
    bool supplied=false;
    assert(takeOptions(args,session,s,supplied,4) && args.size()==4 && session=="mcp-a" && supplied && s.theme=="minimal" && s.reducedMotion && s.motionMs==250);
    args={"window","1","2","cursor_session=mcp-a","theme=gradient"};
    assert(takeOptions(args,session,s,supplied,3) && args.size()==3 && session=="mcp-a" && supplied && s.theme=="gradient");
    args={"window","1","2","move","theme=gradient","theme=minimal"};
    assert(!takeOptions(args,session,s,supplied,4));
    args={"window","1","2","move","motion_ms=3001"};
    assert(!takeOptions(args,session,s,supplied,4));
    for (const auto& val : {"nan","inf","1e3","-1","450x","9999999999999999999999",""}) assert(!option(s,"motion_ms",val));
    assert(option(s,"motion_ms","3000")); assert(!option(s,"motion_ms","3001"));
    assert(!option(s,"idle_ms","0")); assert(option(s,"fade_ms","0"));
    assert(!option(s,"theme","../../theme.lottie")); assert(option(s,"theme","minimal"));
    assert(!option(s,"unknown","1")); assert(!option(s,"reduced_motion","2"));
    assert(color("a-session") == color("a-session"));
    assert((color("legacy") == std::array<uint8_t,3>{94,192,232}));
    bool different = false;
    for (int i=0;i<30;++i) different |= color("session-"+std::to_string(i)) != color("a-session");
    assert(different);
    s=Settings{};
    auto start=Point{10,20},target=Point{300,160};
    auto first=position(start,target,0,s),last=position(start,target,450,s);
    assert(first.x==start.x && first.y==start.y);
    assert(last.x==target.x && last.y==target.y);
    for(int age=0;age<=450;++age) {
        auto p=position(start,target,age,s);
        assert(std::isfinite(p.x) && std::isfinite(p.y));
    }
    auto midpoint=position(start,target,225,s);
    s.arc=0; auto straight=position(start,target,225,s);
    assert(midpoint.x!=straight.x && midpoint.y!=straight.y);
    s.spring=0; auto soft=position(start,target,225,s);
    assert(soft.x!=straight.x);
    s.reducedMotion=true;
    assert(position(start,target,0,s).x==target.x);
    assert(frame(100,s,1)==0); assert(frame(600,s,1)==8);
    s=Settings{};
    assert(opacity(30000,s)==1); assert(opacity(30100,s)==0.5); assert(opacity(30200,s)==0);
    Sessions<> registry;
    auto* a=registry.get("a",0); a->updated=0;
    auto* b=registry.get("b",0); b->updated=1000;
    assert(registry.end("a")); assert(!registry.end("a")); assert(registry.entries.contains("b"));
    registry.expire(31199); assert(registry.entries.contains("b"));
    registry.expire(31200); assert(registry.entries.empty());
    for(size_t i=0;i<MAX_SESSIONS;++i) assert(registry.get("s"+std::to_string(i),0));
    assert(!registry.get("overflow",0)); assert(registry.get("s0",0));
    registry.expire(30200); assert(registry.get("fresh",30200));
    assert(feedback("click")==1 && feedback("type")==2 && feedback("scroll")==3 && feedback("drag")==4);
    s=Settings{};
    auto idle=raster(color("a"),s,0,8);
    assert(idle.size()==TILE*TILE*4);
    for(int cue=1;cue<=4;++cue) {
        auto active=raster(color("a"),s,cue,0);
        assert(active != idle);
        for(size_t i=0;i<active.size();i+=4) {
            assert(active[i]<=active[i+3] && active[i+1]<=active[i+3] && active[i+2]<=active[i+3]);
        }
    }
    auto glow=idle; s.theme="classic"; assert(raster(color("a"),s,0,8)!=glow);
    std::cout << "cursor visual lifecycle/motion/color/settings/raster tests passed\n";
}
