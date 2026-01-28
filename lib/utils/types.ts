const ARRAY_TYPE_INDEX = 1;
const TYPE_SIZE_64_BIT = 8;
const TYPE_SIZE_CHAR = 1;

// eslint-disable-next-line @typescript-eslint/naming-convention
const Types = {

    isComplexObjectType (type: string): boolean {
        const JOBJECT = [
            "jobject",
            "jclass",
            "jweak"  
        ];

        return JOBJECT.includes(type);
    },
    sizeOf (type: NativeFunctionArgumentType | NativeFunctionReturnType): number {
        if (type === "double" || type === "float" || type === "int64") {
            return TYPE_SIZE_64_BIT;
        } else if (type === "char") {
            return TYPE_SIZE_CHAR;
        } else {
            return Process.pointerSize;
        }
    },
    convertNativeJTypeToFridaType (jtype: string): string {
        if (jtype.endsWith("*")) {
            return "pointer";
        }
        if (jtype === "va_list") {
            return "pointer";
        }
        if (jtype === "jmethodID") {
            return "pointer";
        }
        if (jtype === "jfieldID") {
            return "pointer";
        }
        if (jtype === "jweak") {
            jtype = "jobject";
        }
        if (jtype === "jthrowable") {
            jtype = "jobject";
        }
        if (jtype.includes("Array")) {
            jtype = "jarray";
        }
        if (jtype === "jarray") {
            jtype = "jobject";
        }
        if (jtype === "jstring") {
            jtype = "jobject";
        }
        if (jtype === "jclass") {
            jtype = "jobject";
        }
        if (jtype === "jobject") {
            return "pointer";
        }
        if (jtype === "jsize") {
            jtype = "jint";
        }
        if (jtype === "jdouble") {
            return "double";
        }
        if (jtype === "jfloat") {
            return "float";
        }
        if (jtype === "jchar") {
            return "uint16";
        }
        if (jtype === "jboolean") {
            return "char";
        }
        if (jtype === "jlong") {
            return "int64";
        }
        if (jtype === "jint") {
            return "int";
        }
        if (jtype === "jshort") {
            return "int16";
        }
        if (jtype === "jbyte") {
            return "char";
        }

        return jtype;
    },
    convertNativeFunctionArgumentValueToString(arg: Exclude<NativeFunctionArgumentValue, undefined>): string {
        if (typeof arg === 'object' && 'handle' in arg) {
            return arg.handle.toString();
        }

        if (arg instanceof NativePointer || arg instanceof Int64 || arg instanceof UInt64 || typeof arg !== 'object') {
            return String(arg);
        }

        throw new Error(`Unhandled native type: ${typeof arg}`);
    },
    convertNativeJTypeToFridaNativeFunctionArgumentType(jtype: string): NativeFunctionArgumentType {
      if (jtype.endsWith("*")) return "pointer";
      if (jtype.includes("Array")) return "pointer";

      switch (jtype) {
        case "va_list":
        case "jmethodID":
        case "jfieldID":
        case "jweak":
        case "jthrowable":
        case "jarray":
        case "jstring":
        case "jclass":
        case "jobject":
          return "pointer";

        case "jsize":
          return "int";

        case "jdouble":
          return "double";
        case "jfloat":
          return "float";
        case "jchar":
          return "uint16";
        case "jboolean":
          return "char";
        case "jlong":
          return "int64";
        case "jint":
          return "int";
        case "jshort":
          return "int16";
        case "jbyte":
          return "char";

        case "void":
          return "void";

        default:
          throw new Error(`Unsupported JNI type for NativeFunction: ${jtype}`);
      }
    },
    convertNativeFunctionArgumentToNativeCallbackArgument(t: NativeFunctionArgumentType): NativeCallbackArgumentType {
      switch (t) {
        case "...":
          throw new Error("NativeCallback cannot be variadic ('...').");
        case "void":
        case "pointer":
        case "size_t":
        case "ssize_t":
        case "int64":
        case "uint64":
        case "int":
        case "uint":
        case "long":
        case "ulong":
        case "char":
        case "uchar":
        case "float":
        case "double":
        case "int8":
        case "uint8":
        case "int16":
        case "uint16":
        case "int32":
        case "uint32":
        case "bool":
          return t;
        default:
            throw new Error(`Unsupported JNI type for NativeCallback: ${t.toString()}`);
      }
    },
    convertNativeJTypeToFridaNativeFunctionReturnType(jtype: string): NativeFunctionReturnType {
      if (jtype.endsWith("*")) return "pointer";
      if (jtype.includes("Array")) return "pointer";

      switch (jtype) {
        case "va_list":
        case "jmethodID":
        case "jfieldID":
        case "jweak":
        case "jthrowable":
        case "jarray":
        case "jstring":
        case "jclass":
        case "jobject":
          return "pointer";

        case "jsize":
          return "int";

        case "jdouble":
          return "double";
        case "jfloat":
          return "float";
        case "jchar":
          return "uint16";
        case "jboolean":
          return "char";
        case "jlong":
          return "int64";
        case "jint":
          return "int";
        case "jshort":
          return "int16";
        case "jbyte":
          return "char";

        case "void":
          return "void";

        default:
          throw new Error(`Unsupported JNI return type for NativeFunction: ${jtype}`);
      }
    },
    assertPtr(val: unknown, label: string): NativePointer {
        if (!(val instanceof NativePointer)) {
            throw new TypeError(`[${label}] Expected NativePointer, got ${typeof val}`);
        }
        return val;
    },
    assertNum(val: unknown, label: string): number {
        if (typeof val !== 'number') {
            throw new TypeError(`[${label}] Expected number, got ${typeof val}`);
        }
        return val;
    },
    isInvocationContext(context: InvocationContext | CallbackContext): context is InvocationContext {
        return "threadId" in context;
    },
    isCallbackContext(context: InvocationContext | CallbackContext): context is CallbackContext {
        return !Types.isInvocationContext(context);
    },
    assertIsNotVariadicType(
        val: NativeFunctionArgumentType,
        label?: string,
    ): NativeCallbackArgumentType {
        // eslint-disable-next-line @typescript-eslint/no-magic-numbers
        if (val === "...") {
            throw new Error(`${label === undefined ? "" : label + ": "}Cannot use variadic type in NativeCallback`);
        }
    
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion
        return val as NativeCallbackArgumentType;
    },
    assertHasNoVariadicTypes(
        val: NativeFunctionArgumentType[],
        label: string
    ): NativeCallbackArgumentType[] {
        // eslint-disable-next-line @typescript-eslint/no-magic-numbers
        if (val.length > 0 && val[val.length - 1] === "...") {
            throw new Error(`${label}: Cannot use variadic type in NativeCallback`);
        }
    
        // eslint-disable-next-line @typescript-eslint/no-unsafe-type-assertion
        return val as NativeCallbackArgumentType[];
    },
    convertJTypeToNativeJType (jtype: string): string {
        let result = "";
        let isArray = false;

        if (jtype.startsWith("[")) {
            isArray = true;
            jtype = jtype.substring(ARRAY_TYPE_INDEX);
        }

        if (jtype === "B") {
            result += "jbyte";
        } else if (jtype === "S") {
            result += "jshort";
        } else if (jtype === "I") {
            result += "jint";
        } else if (jtype === "J") {
            result += "jlong";
        } else if (jtype === "F") {
            result += "jfloat";
        } else if (jtype === "D") {
            result += "jdouble";
        } else if (jtype === "C") {
            result += "jchar";
        } else if (jtype === "Z") {
            result += "jboolean";
        } else if (jtype.startsWith("L")) {
            if (jtype === "Ljava/lang/String;") {
                result += "jstring";
            } else if (jtype === "Ljava/lang/Class;") {
                result += "jclass";
            } else {
                result += "jobject";
            }
        }

        if (isArray) {
            if (result === "jstring") {
                result = "jobject";
            }
            result += "Array";
        }

        return result;
    }
};

export { Types };
