import os


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
FHE_OPS_LIB_DIR = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))


def snake_case(name):
    result = ""
    for i, c in enumerate(name):
        if c.isupper():
            if i != 0:
                result += "_"
            result += c.lower()
        else:
            result += c
    return result


def load_comments(path):
    comments = {}
    if not os.path.isfile(path):
        return comments

    with open(path, "r") as f:
        old_fhe_lib_h = f.readlines()[6:]

    in_comment = False
    comment_lines = []
    for line in old_fhe_lib_h:
        line_s = line.rstrip()
        if line_s.startswith("/*"):
            in_comment = True
        if in_comment:
            comment_lines.append(line_s)
            if line_s.endswith("*/"):
                in_comment = False
        else:
            if line_s == "":
                continue
            p_pos = line_s.find("(")
            func_name = line_s[:p_pos].split(" ")[-1][2:]
            if comment_lines:
                comments[func_name] = comment_lines
                comment_lines = []

    return comments


def main():
    comments = load_comments(os.path.join(FHE_OPS_LIB_DIR, "fhe_lib.h"))

    with open(os.path.join(SCRIPT_DIR, "liblattigo.h"), "r") as f:
        liblattigo = f.readlines()

    start_line = 0
    for i, line in enumerate(liblattigo):
        if line.startswith('extern "C" {'):
            start_line = i + 3
            break

    with open(os.path.join(FHE_OPS_LIB_DIR, "fhe_lib_v2.h"), "w") as h_f, open(
        os.path.join(FHE_OPS_LIB_DIR, "fhe_lib_v2.c"), "w"
    ) as c_f:
        h_f.write("/** @file */\n")
        h_f.write("\n")
        h_f.write("#pragma once\n")
        h_f.write("#include <inttypes.h>\n")
        h_f.write('#include "fhe_types.h"\n')
        h_f.write("\n")

        c_f.write('#include "lattigo/go_sdk/liblattigo.h"\n')
        c_f.write('#include "fhe_lib.h"\n')
        c_f.write("\n")

        for line in liblattigo[start_line:-4]:
            c_line = line.rstrip().replace("extern ", "").replace("GoUint64", "uint64_t").replace("GoInt", "int")
            p_pos = c_line.find("(")
            func_name = c_line[:p_pos].split(" ")[-1]
            lower_func_name = snake_case(func_name)

            return_type = c_line[:p_pos].replace(" " + func_name, "")
            arguments = c_line[p_pos + 1 : -2].split(", ")
            argument_names = [x.split(" ")[-1] for x in arguments]
            argument_types = [arguments[i].replace(" " + argument_names[i], "") for i in range(len(arguments))]

            if lower_func_name in comments:
                for comment_line in comments[lower_func_name]:
                    h_f.write(comment_line + "\n")

            signature = ", ".join([x + " " + y for x, y in zip(argument_types, argument_names)])
            h_f.write(return_type + " c_" + lower_func_name + "(" + signature + ");\n")
            h_f.write("\n")

            c_f.write("inline " + return_type + " c_" + lower_func_name + "(" + signature + ") {\n")
            c_f.write("    " + ("" if return_type == "void" else "return ") + func_name + "(" + ", ".join(argument_names) + ");\n")
            c_f.write("}\n\n")


if __name__ == "__main__":
    main()
