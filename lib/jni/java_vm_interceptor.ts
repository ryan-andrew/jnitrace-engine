import type { JNIThreadManager } from "./jni_thread_manager";
import type { JNIEnvInterceptor } from "./jni_env_interceptor";
import { JavaVM } from "./java_vm";

import { Types } from "../utils/types";
import type { ReferenceManager } from "../utils/reference_manager";
import type { JNICallbackManager } from "../internal/jni_callback_manager";
import type { JNIInvocationContext } from "../";
import { Config } from "../utils/config";

const JAVA_VM_INDEX = 0;
const JNI_OK = 0;
const JNI_ENV_INDEX = 1;

class JavaVMInterceptor {
    private readonly references: ReferenceManager;

    private readonly threads: JNIThreadManager;

    private readonly jniEnvInterceptor: JNIEnvInterceptor;

    // eslint-disable-next-line @typescript-eslint/no-unused-private-class-members
    private readonly callbackManager: JNICallbackManager;

    private shadowJavaVM: NativePointer;

    // eslint-disable-next-line @typescript-eslint/max-params
    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        jniEnvInterceptor: JNIEnvInterceptor,
        callbackManager: JNICallbackManager
    ) {
        this.references = references;
        this.threads = threads;
        this.jniEnvInterceptor = jniEnvInterceptor;
        this.callbackManager = callbackManager;

        this.shadowJavaVM = NULL;
    }

    private static getThreadId(ctx: InvocationContext | CallbackContext): number {
      if ("threadId" in ctx) {
        return ctx.threadId;
      }
      return Process.getCurrentThreadId();
    }

    public isInitialised (): boolean {
        return !this.shadowJavaVM.isNull();
    }

    public get (): NativePointer {
        return this.shadowJavaVM;
    }

    public create (): NativePointer {
        const javaVMOffset = 3;
        const javaVMLength = 8;
        const javaVM = this.threads.getJavaVM();

        const newJavaVMStruct = Memory.alloc(Process.pointerSize * javaVMLength);
        this.references.add(newJavaVMStruct);

        const newJavaVM = Memory.alloc(Process.pointerSize);
        newJavaVM.writePointer(newJavaVMStruct);

        for (let i = javaVMOffset; i < javaVMLength; i++) {
            const offset = i * Process.pointerSize;
            const javaVMStruct = javaVM.readPointer();
            const methodAddr = javaVMStruct.add(offset).readPointer();

            const callback = this.createJavaVMIntercept(i, methodAddr);
            const trampoline = this.jniEnvInterceptor.createStubFunction();
            this.references.add(trampoline);
            // ensure the CpuContext will be populated
            Interceptor.replace(trampoline, callback);
            newJavaVMStruct.add(offset).writePointer(trampoline);
        }

        this.shadowJavaVM = newJavaVM;

        return newJavaVM;
    }

    private createJavaVMIntercept (
        id: number,
        methodAddr: NativePointer
    ): NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]> {
        const self = this;
        const method = JavaVM.getInstance().methods[id];
        const config = Config.getInstance();
        const fridaArgs = method.args.map(
            (a: string) => Types.convertNativeJTypeToFridaNativeFunctionArgumentType(a)
        );
        const fridaRet = Types.convertNativeJTypeToFridaNativeFunctionReturnType(method.ret);

        const nativeFunction = new NativeFunction(methodAddr, fridaRet, fridaArgs);
        const invoke = nativeFunction as ((...a: NativeFunctionArgumentValue[]) => NativeFunctionReturnValue);

        const nativeCallback = new NativeCallback(function (
            this: InvocationContext | CallbackContext,
            ...args: NativeCallbackArgumentValue[]
        ): NativeCallbackReturnValue {
            const threadId = JavaVMInterceptor.getThreadId(this);
            const javaVM = self.threads.getJavaVM();

            const localArgs = args.slice();
            let jniEnv: NativePointer = NULL;

            localArgs[JAVA_VM_INDEX] = javaVM;

            const ctx: JNIInvocationContext = {
                methodDef: method,
                jniAddress: methodAddr,
                threadId: threadId
            };

            if (config.backtrace === "accurate") {
                ctx.backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE);
            } else if (config.backtrace === "fuzzy") {
                ctx.backtrace = Thread.backtrace(this.context, Backtracer.FUZZY);
            }

            self.callbackManager.doBeforeCallback(method.name, ctx, localArgs);

            let ret = invoke(...localArgs);

            ret = self.callbackManager.doAfterCallback(method.name, ctx, ret);

            if (method.name === "GetEnv" ||
                    method.name === "AttachCurrentThread" ||
                    method.name === "AttachCurrentThreadAsDaemon"
            ) {
                const envOut = localArgs[JNI_ENV_INDEX];
                if (!(envOut instanceof NativePointer)) {
                  throw new Error(`Expected JNI_ENV_INDEX to be a NativePointer, got: ${typeof envOut}`);
                }

                if (ret === JNI_OK) {
                  self.threads.setJNIEnv(threadId, envOut.readPointer());
                }

                if (!self.jniEnvInterceptor.isInitialised()) {
                    jniEnv = self.jniEnvInterceptor.create();
                } else {
                    jniEnv = self.jniEnvInterceptor.get();
                }

                envOut.writePointer(jniEnv);
            }

            return ret;
        }, fridaRet, fridaArgs.map((a) => Types.convertNativeFunctionArgumentToNativeCallbackArgument(a)));

        this.references.add(nativeCallback);

        return nativeCallback;
    }
}

export { JavaVMInterceptor };
