// SPDX-License-Identifier: MIT
// Session palette adapted from Cua cursor-overlay/theme.rs, Copyright (c) 2025-2026 Cua AI, Inc.
// See THIRD_PARTY_CURSOR_NOTICES.md. Raster artwork is original procedural geometry.
#pragma once
#include <algorithm>
#include <array>
#include <charconv>
#include <cmath>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace CursorVisual {
constexpr size_t MAX_SESSIONS = 32;
constexpr int TILE = 96;
struct Point { double x = 0, y = 0; };
struct Settings {
    std::string theme = "gradient";
    int motionMs = 450, arc = 25, spring = 72, idleMs = 30000, fadeMs = 200, size = 42;
    bool reducedMotion = false;
};
inline bool validSession(std::string_view id) {
    return !id.empty() && id.size() <= 64 && std::all_of(id.begin(), id.end(), [](unsigned char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_';
    });
}
inline bool takeSession(std::vector<std::string>& parts, std::string& session) {
    session = "legacy";
    constexpr std::string_view prefix = "cursor_session=";
    if (!parts.empty() && parts.back().starts_with(prefix)) {
        const auto value = std::string_view{parts.back()}.substr(prefix.size());
        if (!validSession(value)) return false;
        session = value;
        parts.pop_back();
    }
    return true;
}
inline bool option(Settings& s, std::string_view key, std::string_view value) {
    if (key == "theme") {
        if (value != "gradient" && value != "classic" && value != "minimal" && value != "codex") return false;
        s.theme = value; return true;
    }
    int n = 0;
    auto [end, err] = std::from_chars(value.data(), value.data() + value.size(), n);
    if (err != std::errc{} || end != value.data() + value.size() || value.empty()) return false;
    auto set = [&](int& field, int lo, int hi) { if (n < lo || n > hi) return false; field = n; return true; };
    if (key == "motion_ms") return set(s.motionMs, 0, 3000);
    if (key == "arc") return set(s.arc, 0, 100);
    if (key == "spring") return set(s.spring, 0, 100);
    if (key == "idle_ms") return set(s.idleMs, 100, 60000);
    if (key == "fade_ms") return set(s.fadeMs, 0, 5000);
    if (key == "size") return set(s.size, 16, 128);
    if (key == "reduced_motion" && (n == 0 || n == 1)) { s.reducedMotion = n != 0; return true; }
    return false;
}
inline bool takeOptions(std::vector<std::string>& parts, std::string& session, Settings& settings, bool& supplied, size_t minimum) {
    session="legacy"; supplied=false;
    std::map<std::string,bool> seen;
    while(parts.size()>minimum) {
        const auto pos=parts.back().find('=');
        if(pos==std::string::npos) break;
        const auto key=parts.back().substr(0,pos),value=parts.back().substr(pos+1);
        const auto canonical=key=="session" ? std::string{"cursor_session"} : key;
        if(seen.size()>=9 || seen.contains(canonical)) return false;
        seen[canonical]=true;
        if(key=="cursor_session" || key=="session") {
            if(!validSession(value)) return false;
            session=value;
        } else {
            if(!option(settings,key,value)) return false;
            supplied=true;
        }
        parts.pop_back();
    }
    return true;
}
inline std::array<uint8_t, 3> color(std::string_view id) {
    constexpr std::array<std::array<uint8_t, 3>, 9> palette{{{178,132,255},{247,132,170},{96,218,174},{244,178,66},{76,204,224},{221,113,236},{232,82,98},{184,220,54},{80,126,236}}};
    if (id.empty() || id == "default" || id == "legacy") return {94,192,232};
    uint32_t hash = 2166136261U;
    for (unsigned char c : id) { hash ^= c; hash *= 16777619U; }
    return palette[hash % palette.size()];
}
inline Point position(Point start, Point target, double age, const Settings& s) {
    if (s.reducedMotion || s.motionMs == 0 || age >= s.motionMs) return target;
    double t = std::clamp(age / s.motionMs, 0.0, 1.0);
    // Closed-form critically damped progress, normalized at arrival: no per-frame integration.
    const double k = 4.0 + s.spring * 0.06;
    const auto spring = [k](double x) { return 1.0 - (1.0 + k * x) * std::exp(-k * x); };
    t = spring(t) / spring(1.0);
    double dx = target.x - start.x, dy = target.y - start.y;
    const double arc = s.arc / 100.0 * 4.0 * t * (1.0 - t);
    return {start.x + dx * t - dy * arc, start.y + dy * t + dx * arc};
}
inline double opacity(double age, const Settings& s) {
    if (age <= s.idleMs) return 1.0;
    if (s.fadeMs == 0) return 0.0;
    return std::clamp(1.0 - (age - s.idleMs) / s.fadeMs, 0.0, 1.0);
}
struct State {
    Settings settings;
    Point start, target, display;
    double updated = 0;
    std::string action;
};
template<class T = State> struct Sessions {
    std::map<std::string, T> entries;
    T* get(std::string_view id, double now) {
        expire(now);
        if (!validSession(id)) return nullptr;
        const auto key = std::string{id};
        if (!entries.contains(key) && entries.size() >= MAX_SESSIONS) return nullptr;
        return &entries.try_emplace(key).first->second;
    }
    bool end(std::string_view id) { return entries.erase(std::string{id}) != 0; }
    void expire(double now) {
        std::erase_if(entries, [now](const auto& e) { return now - e.second.updated >= e.second.settings.idleMs + e.second.settings.fadeMs; });
    }
};
inline int feedback(std::string_view action) {
    if (action == "click" || action == "doubleclick" || action == "double-click" || action == "press" || action == "down" || action == "release" || action == "up") return 1;
    if (action == "type" || action == "typing" || action == "key" || action == "set_value" || action == "paste") return 2;
    if (action == "scroll") return 3;
    if (action == "drag" || action == "dragging") return 4;
    return 0;
}
inline int frame(double age, const Settings& s, int cue) {
    if (!cue || age >= 600) return 8;
    return s.reducedMotion ? 0 : std::clamp(static_cast<int>(age / 75), 0, 7);
}
// Original, bounded, premultiplied-alpha tile. Hotspot is (36,32); size is arrow height (36px).
inline std::vector<uint8_t> raster(std::array<uint8_t,3> rgb, const Settings& s, int cue, int frame) {
    std::vector<uint8_t> out(TILE * TILE * 4);
    constexpr std::array<Point,7> arrow{{{36,32},{36,65},{44,57},{51,70},{57,67},{50,54},{62,54}}};
    auto segment = [](Point p, Point a, Point b) {
        double dx = b.x-a.x, dy = b.y-a.y;
        double t = std::clamp(((p.x-a.x)*dx+(p.y-a.y)*dy)/(dx*dx+dy*dy),0.0,1.0);
        return std::hypot(p.x-a.x-t*dx,p.y-a.y-t*dy);
    };
    for (int y=0;y<TILE;++y) for(int x=0;x<TILE;++x) {
        Point p{x+0.5,y+0.5};
        double r=rgb[0]/255.0,g=rgb[1]/255.0,b=rgb[2]/255.0;
        double dist=std::hypot(p.x-43,p.y-48), a=0;
        if(s.theme=="gradient") a=0.20*std::exp(-dist*dist/380.0);
        bool inside=false; double edge=1e9;
        for(size_t i=0,j=arrow.size()-1;i<arrow.size();j=i++) {
            const auto u=arrow[i],v=arrow[j];
            if((u.y>p.y)!=(v.y>p.y) && p.x<(v.x-u.x)*(p.y-u.y)/(v.y-u.y)+u.x) inside=!inside;
            edge=std::min(edge,segment(p,u,v));
        }
        if(s.theme != "codex" && (inside || edge<1.4)) {
            a=std::clamp(1.9-edge,0.0,1.0);
            if(inside) a=1;
            if(edge<1.3) {r=g=b=0.98;} else if(s.theme=="gradient") {
                double mix=std::clamp((70-p.y)/55.0,0.0,0.65);
                r+= (1-r)*mix; g+=(1-g)*mix; b+=(1-b)*mix;
            } else if(s.theme=="minimal") {r=g=b=0.98;}
        }
        bool mark=false;
        if(frame<8) {
            const double phase=frame/8.0;
            if(cue==1) {
                double ring=std::hypot(p.x-36,p.y-32);
                mark=std::abs(ring-(9+phase*18))<1.6;
            } else if(cue==2) { // three keyboard keycaps
                for(int i=0;i<3;++i) if(p.x>57+i*9 && p.x<64+i*9 && p.y>72 && p.y<80) mark=true;
            } else if(cue==3) { // directional double chevrons
                for(double cy : {35.0,68.0})
                    if(segment(p,{69,cy+4},{75,cy})<1.6 || segment(p,{75,cy},{81,cy+4})<1.6) mark=true;
            } else if(cue==4) { // tether / held pointer badge
                mark=segment(p,{12,76},{30,59})<1.7 || std::abs(std::hypot(p.x-12,p.y-76)-5)<1.5;
            }
        }
        if(mark) { r=rgb[0]/255.0;g=rgb[1]/255.0;b=rgb[2]/255.0;a=0.95; }
        auto index=(y*TILE+x)*4;
        out[index]=static_cast<uint8_t>(std::clamp(r*a,0.0,1.0)*255);
        out[index+1]=static_cast<uint8_t>(std::clamp(g*a,0.0,1.0)*255);
        out[index+2]=static_cast<uint8_t>(std::clamp(b*a,0.0,1.0)*255);
        out[index+3]=static_cast<uint8_t>(std::clamp(a,0.0,1.0)*255);
    }
    return out;
}
}
