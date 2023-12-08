#include <android/log.h>
#include <sys/system_properties.h>
#include <unistd.h>
#include <string>
#include <vector>
#include <map>
#include <iostream>
#include "zygisk.hpp"
#include "dobby.h"
#include "json.hpp"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "PIF/Native", __VA_ARGS__)

static std::string SECURITY_PATCH, FIRST_API_LEVEL;

#define DEX_FILE_PATH "/data/adb/modules/bypassKeyAttestation/classes.dex"

#define JSON_FILE_PATH "/data/adb/pif.json"

typedef void (*T_Callback)(void *, const char *, const char *, uint32_t);

static std::map<void *, T_Callback> callbacks;

static void modify_callback(void *cookie, const char *name, const char *value, uint32_t serial) {

    if (cookie == nullptr || name == nullptr || value == nullptr ||
        !callbacks.contains(cookie))
        return;

    std::string_view prop(name);

    if (prop.ends_with("api_level")) {
        if (FIRST_API_LEVEL.empty()) {
            value = nullptr;
        } else {
            value = FIRST_API_LEVEL.c_str();
        }
    } else if (prop.ends_with("security_patch")) {
        if (SECURITY_PATCH.empty()) {
            value = nullptr;
        } else {
            value = SECURITY_PATCH.c_str();
        }
    }

    if (!prop.starts_with("cache") && !prop.starts_with("debug")) LOGD("[%s] -> %s", name, value);

    return callbacks[cookie](cookie, name, value, serial);
}

static void (*o_system_property_read_callback)(const prop_info *, T_Callback, void *);

static void
my_system_property_read_callback(const prop_info *pi, T_Callback callback, void *cookie) {

    if (pi == nullptr || callback == nullptr || cookie == nullptr) {
        return o_system_property_read_callback(pi, callback, cookie);
    }
    callbacks[cookie] = callback;
    return o_system_property_read_callback(pi, modify_callback, cookie);
}

static void doHook() {
    void *handle = DobbySymbolResolver("libc.so", "__system_property_read_callback");
    if (handle == nullptr) {
        LOGD("Couldn't find '__system_property_read_callback' handle. Report to @chiteroman");
        return;
    }
    LOGD("Found '__system_property_read_callback' handle at %p", handle);
    DobbyHook(handle, (void *) my_system_property_read_callback,
              (void **) &o_system_property_read_callback);
}

class bypassKeyAttestation : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        bool isKeyAttestation = false;

        auto process = env->GetStringUTFChars(args->nice_name, nullptr);

        if (process) {
            isKeyAttestation = strncmp(process, "io.github.vvb2060.keyattestation" , strlen("io.github.vvb2060.keyattestation")) == 0;
        }

        if(!isKeyAttestation){
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return ;
        }

        env->ReleaseStringUTFChars(args->nice_name, process);

        api->setOption(zygisk::FORCE_DENYLIST_UNMOUNT);

        long dexSize = 0, jsonSize = 0;
        int fd = api->connectCompanion();

        read(fd, &dexSize, sizeof(long));
        read(fd, &jsonSize, sizeof(long));

        if (dexSize < 1) {
            close(fd);
            LOGD("Couldn't read classes.dex");
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        if (jsonSize < 1) {
            close(fd);
            LOGD("Couldn't read pif.json");
            api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
            return;
        }

        dexVector.resize(dexSize);
        read(fd, dexVector.data(), dexSize);

        std::vector<char> jsonVector(jsonSize);
        read(fd, jsonVector.data(), jsonSize);

        close(fd);

        LOGD("Read from file descriptor file 'classes.dex' -> %ld bytes", dexSize);
        LOGD("Read from file descriptor file 'pif.json' -> %ld bytes", jsonSize);

        std::string data(jsonVector.cbegin(), jsonVector.cend());
        json = nlohmann::json::parse(data, nullptr, false, true);

        jsonVector.clear();
        data.clear();

    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (dexVector.empty() || json.empty()) return;

        readJson();

//        doHook();

        inject();

        LOGD("clean");
        dexVector.clear();
        dexVector.shrink_to_fit();
    }


    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::vector<char> dexVector;
    nlohmann::json json;

    void inject() {
        LOGD("get system classloader");
        auto clClass = env->FindClass("java/lang/ClassLoader");
        if(env->ExceptionOccurred()){
            LOGD("env->FindClass ExceptionOccurred");
            env->ExceptionDescribe();
        }
        auto getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader",
                                                           "()Ljava/lang/ClassLoader;");
        if(env->ExceptionOccurred()){
            LOGD("getSystemClassLoader ExceptionOccurred");
            env->ExceptionDescribe();
        }

        auto systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);
        if(env->ExceptionOccurred()){
            LOGD("systemClassLoader ExceptionOccurred");
            env->ExceptionDescribe();
        }

        LOGD("create class loader");
        auto dexClClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        if(env->ExceptionOccurred()){
            LOGD("dexClClass ExceptionOccurred");
            env->ExceptionDescribe();
        }

        auto dexClInit = env->GetMethodID(dexClClass, "<init>",
                                          "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        if(env->ExceptionOccurred()){
            LOGD("dexClInit ExceptionOccurred");
            env->ExceptionDescribe();
        }
        auto buffer = env->NewDirectByteBuffer(dexVector.data(),
                                               static_cast<jlong>(dexVector.size()));
        if(env->ExceptionOccurred()){
            LOGD("buffer ExceptionOccurred");
            env->ExceptionDescribe();
        }

        auto dexCl = env->NewObject(dexClClass, dexClInit, buffer, systemClassLoader);

        if(env->ExceptionOccurred()){
            LOGD("create class loader ExceptionOccurred");
            env->ExceptionDescribe();
        }

        LOGD("load class");
        auto loadClass = env->GetMethodID(clClass, "loadClass",
                                          "(Ljava/lang/String;)Ljava/lang/Class;");
        if(env->ExceptionOccurred()){
            LOGD("GetMethodID ExceptionOccurred");
            env->ExceptionDescribe();
        }
        auto entryClassName = env->NewStringUTF("com.pareto.bypasskeyattestation.EntryPoint");
        if(env->ExceptionOccurred()){
            LOGD("entryClassName ExceptionOccurred");
            env->ExceptionDescribe();
        }
        auto entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);
        if(env->ExceptionOccurred()){
            LOGD("entryClassObj ExceptionOccurred");
            env->ExceptionDescribe();
        }

        auto entryClass = (jclass) entryClassObj;

        LOGD("call init");
        auto entryInit = env->GetStaticMethodID(entryClass, "init", "(Ljava/lang/String;)V");
        auto javaStr = env->NewStringUTF(json.dump().c_str());
        env->CallStaticVoidMethod(entryClass, entryInit, javaStr);
    }

    void readJson() {
        LOGD("JSON contains %d keys!", static_cast<int>(json.size()));

        if (json.contains("SECURITY_PATCH")) {
            if (json["SECURITY_PATCH"].is_null()) {
                LOGD("Key SECURITY_PATCH is null!");
            } else if (json["SECURITY_PATCH"].is_string()) {
                SECURITY_PATCH = json["SECURITY_PATCH"].get<std::string>();
            } else {
                LOGD("Error parsing SECURITY_PATCH!");
            }
        } else {
            LOGD("Key SECURITY_PATCH doesn't exist in JSON file!");
        }

        if (json.contains("FIRST_API_LEVEL")) {
            if (json["FIRST_API_LEVEL"].is_null()) {
                LOGD("Key FIRST_API_LEVEL is null!");
            } else if (json["FIRST_API_LEVEL"].is_string()) {
                FIRST_API_LEVEL = json["FIRST_API_LEVEL"].get<std::string>();
            } else {
                LOGD("Error parsing FIRST_API_LEVEL!");
            }
            json.erase("FIRST_API_LEVEL");
        } else {
            LOGD("Key FIRST_API_LEVEL doesn't exist in JSON file!");
        }
    }
};



static void companion(int fd) {
    long dexSize = 0, jsonSize = 0;
    std::vector<char> dexVector, jsonVector;

    FILE *dex = fopen(DEX_FILE_PATH, "rb");

    if (dex) {
        fseek(dex, 0, SEEK_END);
        dexSize = ftell(dex);
        fseek(dex, 0, SEEK_SET);

        dexVector.resize(dexSize);
        fread(dexVector.data(), 1, dexSize, dex);

        fclose(dex);
    }

    FILE *json;

    if (std::filesystem::exists(JSON_FILE_PATH)) {

        json = fopen(JSON_FILE_PATH, "rb");

    }
    else{

        LOGD("read file error");
    }

    if (json) {
        fseek(json, 0, SEEK_END);
        jsonSize = ftell(json);
        fseek(json, 0, SEEK_SET);

        jsonVector.resize(jsonSize);
        fread(jsonVector.data(), 1, jsonSize, json);

        fclose(json);
    }

    write(fd, &dexSize, sizeof(long));
    write(fd, &jsonSize, sizeof(long));

    write(fd, dexVector.data(), dexSize);
    write(fd, jsonVector.data(), jsonSize);

    dexVector.clear();
    jsonVector.clear();
}

REGISTER_ZYGISK_MODULE(bypassKeyAttestation)

REGISTER_ZYGISK_COMPANION(companion)