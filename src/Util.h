#pragma once
#include <ctype.h>
#include <stdio.h>

#include <mutex>
#include <queue>
#include <thread>

#include "RakPeerInterface.h"
#include "napi.h"

// Holds the context for our RakNet thread
struct TsfnContext {
    TsfnContext(Napi::Env env) : deferred(Napi::Promise::Deferred::New(env)){};
    Napi::Promise::Deferred deferred;  // Don't allow JS to gc until server is closed
    bool running = true;
    RakNet::RakPeerInterface* rakPeer = nullptr;
    std::thread nativeThread;
    Napi::ThreadSafeFunction tsfn;
};

// Called when our RakNet thread needs to close
void FinalizerCallback(Napi::Env env, void* finalizeData, TsfnContext* context);

// Copy of RakNet::Packet
struct JSPacket {
    RakNet::SystemAddress systemAddress;
    RakNet::AddressOrGUID guid;
    unsigned int length = 0;
    unsigned char* data = 0;
};

inline JSPacket* CreateJSPacket(RakNet::Packet* p) {
    auto jsData = new JSPacket{p->systemAddress, p->guid, p->length};
    jsData->data = new unsigned char[p->length];
    memcpy(jsData->data, p->data, p->length);
    return jsData;
}

inline void FreeJSPacket(JSPacket* p) {
    delete[] p->data;
    delete p;
}

inline void FreeBuf(Napi::Env env, void* buf, JSPacket* hint) { FreeJSPacket((JSPacket*)hint); }

// Moves every queued packet out of the shared queue, holding the lock only for the swap
inline std::queue<JSPacket*> TakePackets(std::queue<JSPacket*>& queue, std::mutex& mutex) {
    std::queue<JSPacket*> taken;
    std::lock_guard<std::mutex> lock(mutex);
    std::swap(taken, queue);
    return taken;
}

// Frees queued packets that will never be handed to JS
inline void DiscardPackets(std::queue<JSPacket*>& queue, std::mutex& mutex) {
    auto pending = TakePackets(queue, mutex);
    for (; !pending.empty(); pending.pop()) FreeJSPacket(pending.front());
}

// Hex tools

unsigned char GetPacketIdentifier2(RakNet::Packet* p);  // get first byte of packet
void hexdump(void* ptr, int buflen);                    // dump packet