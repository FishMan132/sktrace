const arm64CM = new CModule(`
#include <gum/gumstalker.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

extern void on_message(const gchar *message);
static void log(const gchar *format, ...);
static void on_arm64_before(GumCpuContext *cpu_context, gpointer user_data);
static void on_arm64_after(GumCpuContext *cpu_context, gpointer user_data);

void hello() {
    on_message("Hello form CModule");
}

gpointer shared_mem[] = {0, 0};

gpointer 
get_shared_mem() 
{
    return shared_mem;
}


static void
log(const gchar *format, ...)
{
    gchar *message;
    va_list args;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    on_message(message);
    g_free(message);
}


void transform(GumStalkerIterator *iterator,
               GumStalkerOutput *output,
               gpointer user_data)
{
    cs_insn *insn;

    gpointer base = *(gpointer*)user_data;
    gpointer end = *(gpointer*)(user_data + sizeof(gpointer));
    
    while (gum_stalker_iterator_next(iterator, &insn))
    {
        gboolean in_target = (gpointer)insn->address >= base && (gpointer)insn->address < end;
        if(in_target)
        {
            log("%p\t%s\t%s", (gpointer)insn->address, insn->mnemonic, insn->op_str);
            gum_stalker_iterator_put_callout(iterator, on_arm64_before, (gpointer) insn->address, NULL);
        }
        gum_stalker_iterator_keep(iterator);
        if(in_target) 
        {
            gum_stalker_iterator_put_callout(iterator, on_arm64_after, (gpointer) insn->address, NULL);
        }
    }
}


const gchar * cpu_format = "
    0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x\t0x%x\t0x%x
    \t0x%x\t0x%x\t0x%x
    ";

static void
on_arm64_before(GumCpuContext *cpu_context,
        gpointer user_data)
{

}

static void
on_arm64_after(GumCpuContext *cpu_context,
        gpointer user_data)
{

}

`, {
    on_message: new NativeCallback(messagePtr => {
        const message = messagePtr.readUtf8String();
        console.log(message)
        // send(message)
    }, 'void', ['pointer']),
});


const userData = Memory.alloc(Process.pageSize);

function stalkerTraceRangeC(tid, base, size) {
    // const hello = new NativeFunction(cm.hello, 'void', []);
    // hello();
    userData.writePointer(base)
    const pointerSize = Process.pointerSize;
    userData.add(pointerSize).writePointer(base.add(size))

    Stalker.follow(tid, {
        transform: arm64CM.transform,
        // onEvent: cm.process,
        data: userData /* user_data */
    })
}


function stalkerTraceRange(tid, startTraceAddr, traceSize, moduleBase) {
    Stalker.follow(tid, {
        transform: (iterator) => {
            const instruction = iterator.next();
            const insAddress = instruction.address;
            const isModuleCode = insAddress.compare(startTraceAddr) >= 0 && insAddress.compare(startTraceAddr.add(traceSize)) < 0;
            // const isModuleCode = true;
            do {
                if (isModuleCode) {
                    // console.log('startAddress: ', insAddress.sub(moduleBase))
                    send({
                        type: 'inst',
                        tid: tid,
                        moduleBase: moduleBase,
                        block: insAddress.sub(moduleBase),
                        val: JSON.stringify(instruction)
                    })
                    iterator.putCallout((context) => {
                        send({
                            type: 'ctx',
                            tid: tid,
                            val: JSON.stringify(context)
                        })
                    })
                }
                iterator.keep();
            } while (iterator.next() !== null);
        }
    })
}


function traceAddr(startTraceAddr, endTraceAddr, moduleBase) {
    let moduleMap = new ModuleMap();
    let targetModule = moduleMap.find(startTraceAddr);
    console.log('targetModule: ', JSON.stringify(targetModule))

    let exports = targetModule.enumerateExports();
    let symbols = targetModule.enumerateSymbols();
    // send({
    //     type: "module", 
    //     targetModule
    // })
    // send({
    //     type: "sym",
    // })
    let traceSize;
    if (endTraceAddr != null) {
        traceSize = endTraceAddr - startTraceAddr;
    } else {
        traceSize = targetModule.size
    }
    console.log('traceSize: ', traceSize, 'startTraceAddr: ', startTraceAddr);
    // var libwechatnetwork = Module.findBaseAddress("libwechatnetwork.so");
    Interceptor.attach(startTraceAddr, {
        onEnter: function (args) {
            console.log('onEnter................................................................');
            this.tid = Process.getCurrentThreadId()
            stalkerTraceRange(this.tid, startTraceAddr, traceSize, moduleBase)
        },
        onLeave: function (ret) {
            Stalker.unfollow(this.tid);
            Stalker.garbageCollect()
            send({
                type: "fin",
                tid: this.tid,
            })
        }
    })
}


function traceSymbol(symbol) {

}

/**
 * from jnitrace-egine
 */
function watcherLib(libname, callback) {
    const dlopenRef = Module.findExportByName(null, "dlopen");
    const dlsymRef = Module.findExportByName(null, "dlsym");
    const dlcloseRef = Module.findExportByName(null, "dlclose");

    if (dlopenRef !== null && dlsymRef !== null && dlcloseRef !== null) {
        const dlopen = new NativeFunction(dlopenRef, "pointer", ["pointer", "int"]);
        Interceptor.replace(dlopen, new NativeCallback((filename, mode) => {
            const path = filename.readCString();
            const retval = dlopen(filename, mode);

            if (path !== null) {
                if (checkLibrary(path)) {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    trackedLibs.set(retval.toString(), true);
                } else {
                    // eslint-disable-next-line @typescript-eslint/no-base-to-string
                    libBlacklist.set(retval.toString(), true);
                }
            }

            return retval;
        }, "pointer", ["pointer", "int"]));
    }
}



(() => {

    console.log(`----- start trace -----`);

    recv("config", (msg) => {
        const payload = msg.payload;
        console.log(JSON.stringify(payload))
        const filename = payload.filename;
        console.log(`filename:${filename}`)

        if (payload.spawn) {
            console.error(`todo: spawn inject not implemented`)
        } else {
            // const modules = Process.enumerateModules();
            const targetModule = Process.getModuleByName(filename);

            let targetAddress = null;
            if ("symbol" in payload) {
                targetAddress = targetModule.findExportByName(payload.symbol);
            } {
                targetAddress = targetModule.base.add(ptr(payload.start_addr));
            }
            console.log('targetAddress: ', targetAddress)

            let endTraceAddr = null;
            if ('end_addr' in payload) {
                endTraceAddr = targetModule.base.add(ptr(payload.end_addr));
            }
            console.log('endTraceAddr: ', endTraceAddr)

            traceAddr(targetAddress, endTraceAddr, targetModule.base)
        }
    })
})()