import { JNIEnvInterceptor } from "../jni_env_interceptor";
import type { JNIThreadManager } from "../jni_thread_manager";

import type { ReferenceManager } from "../../utils/reference_manager";
import { Types } from "../../utils/types";
import type { JavaMethod } from "../../utils/java_method";
import type { JNICallbackManager } from "../../internal/jni_callback_manager";

class JNIEnvInterceptorX86 extends JNIEnvInterceptor {
    private vaList: NativePointer;

    private vaListOffset: number;

    public constructor (
        references: ReferenceManager,
        threads: JNIThreadManager,
        callbackManager: JNICallbackManager
    ) {
        super(references, threads, callbackManager);

        this.vaList = NULL;
        this.vaListOffset = 0;
    }

    // eslint-disable-next-line @typescript-eslint/class-methods-use-this
    protected buildVaArgParserShellcode (
        text: NativePointer,
        _: NativePointer,
        parser: NativeCallback<NativeCallbackReturnType, NativeCallbackArgumentType[]>
    ): void {
        const DATA_OFFSET = 0x400;
        text.add(DATA_OFFSET).writePointer(parser);

        Memory.patchCode(text, Process.pageSize, (code: NativePointer): void => {
            const cw = new X86Writer(code, { pc: text });
            const dataOffset = DATA_OFFSET + Process.pointerSize;

            cw.putPopReg("eax");
            cw.putMovNearPtrReg(
                text.add(dataOffset + Process.pointerSize), "eax"
            );

            cw.putCallAddress(parser);

            cw.putCallReg("eax");

            cw.putJmpNearPtr(text.add(dataOffset + Process.pointerSize));

            cw.flush();
        });
    }

    protected setUpVaListArgExtract (vaList: NativePointer): void {
        this.vaList = vaList;
        this.vaListOffset = 0;
    }

    protected extractVaListArgValue (
        method: JavaMethod,
        paramId: number
    ): NativePointer {
        const currentPtr = this.vaList.add(this.vaListOffset);
        this.vaListOffset += Types.sizeOf(method.fridaParams[paramId]);
        return currentPtr;
    }

    protected resetVaListArgExtract (): void {
        this.vaList = NULL;
        this.vaListOffset = 0;
    }
}

export { JNIEnvInterceptorX86 };
