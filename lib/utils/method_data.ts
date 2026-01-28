import type { JNIMethod } from "../jni/jni_method";
import type { JavaMethod } from "./java_method";

class MethodData {
    private readonly _method: JNIMethod;

    private readonly _jmethod: JavaMethod | undefined;

    private readonly _args: NativeFunctionArgumentValue[];

    private readonly _jparams: string[];

    private readonly _ret: NativeFunctionReturnValue;

    // eslint-disable-next-line @typescript-eslint/max-params
    public constructor (
        method: JNIMethod,
        args: NativeFunctionArgumentValue[],
        ret: NativeFunctionReturnValue,
        jmethod?: JavaMethod
    ) {
        this._method = method;
        this._jmethod = jmethod;
        this._args = args;
        this._ret = ret;
        if (jmethod === undefined) {
            this._jparams = [];
        } else {
            this._jparams = jmethod.nativeParams;
        }
    }

    public get method (): JNIMethod {
        return this._method;
    }

    public get javaMethod (): JavaMethod | undefined {
        return this._jmethod;
    }

    public get args (): NativeFunctionArgumentValue[] {
        return this._args;
    }

    public getArgAsPtr (i: number): NativePointer {
        const arg = this._args[i];
        if (arg instanceof NativePointer) {
            return arg;
        } else {
            throw new Error(`Expected arg ${i} to be a NativePointer, got: ${typeof arg}`);
        }
    }

    public getArgAsNum (i: number): number {
        const arg = this._args[i];
        if (typeof arg === 'number') {
            return arg;
        } else {
            throw new Error(`Expected arg ${i} to be a number, got: ${typeof arg}`);
        }
    }

    // eslint-disable-next-line @typescript-eslint/member-ordering
    public get jParams (): string[] {
        return this._jparams;
    }

    // eslint-disable-next-line @typescript-eslint/member-ordering
    public get ret (): NativeFunctionReturnValue {
        return this._ret;
    }
}

export { MethodData };
