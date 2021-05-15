// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#include <fstream>
#include <map>
#include <regex>
#include <set>
#include <sstream>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <tuple>
#include <typeinfo>
#include <unistd.h>

#include "clang/AST/AST.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendAction.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Rewrite/Core/Rewriter.h"
#include "clang/Tooling/CommonOptionsParser.h"
#include "clang/Tooling/Tooling.h"
#include "llvm/Support/raw_ostream.h"

using namespace clang;
using namespace clang::driver;
using namespace clang::tooling;

// defining the input params so all the program can use them
llvm::cl::OptionCategory parse_fields_tool_category("My tool options");
llvm::cl::extrahelp CommonHelp(CommonOptionsParser::HelpMessage);
llvm::cl::extrahelp MoreHelp("Tool specific flags:\n-output-file-path <file_path> for file path\n");
llvm::cl::opt<std::string> output_file_path("output-file-path", llvm::cl::cat(parse_fields_tool_category));
llvm::cl::alias output_file_path_alias("o", llvm::cl::desc("Alias for -output-file-path"), llvm::cl::aliasopt(output_file_path));
llvm::cl::opt<std::string> config_file("config-file", llvm::cl::desc("configuration file for the tool"));
// llvm::cl::list<std::string> entry_point_dirs("include-dir", llvm::cl::desc("Folder(s) whose contents should be serialized"),
// llvm::cl::OneOrMore);
llvm::cl::list<std::string> module_dirs("module-dir",
                                        llvm::cl::desc("Folders whose contents should be serialized (if used by include dirs)"));
llvm::cl::opt<size_t, false, llvm::cl::parser<int>> num_of_generated_files(
    "num-out-files",
    llvm::cl::desc("Determines how many files to generate in the output. If size is lareger than 1, the output file should contain "
                   "also '%' in it for part number"),
    llvm::cl::init(1));

enum log_level_e { LOG_LEVEL_DEBUG, LOG_LEVEL_PROGRESS, LOG_LEVEL_WARNING, LOG_LEVEL_ERROR, NUM_LOG_LEVELS };
static log_level_e program_log_level = LOG_LEVEL_PROGRESS;
static std::string log_prefixes[NUM_LOG_LEVELS] = {"DEBUG: ", "", "WARNING: ", "ERROR: "};

#define LOG(log_level, message)                                                                                                    \
    do {                                                                                                                           \
        if (log_level >= program_log_level) {                                                                                      \
            llvm::outs() << log_prefixes[log_level] << message << "\n";                                                            \
        }                                                                                                                          \
    } while (0)

#define ELOG(message) LOG(LOG_LEVEL_ERROR, message)
#define WLOG(message) LOG(LOG_LEVEL_WARNING, message)
#define PLOG(message) LOG(LOG_LEVEL_PROGRESS, message)
#define DLOG(message) LOG(LOG_LEVEL_DEBUG, message)

#define DEBUG_PRINT(message)                                                                                                       \
    do {                                                                                                                           \
        llvm::outs() << "debug: " << message << "\n";                                                                              \
        llvm::outs().flush();                                                                                                      \
    } while (0)

// currently insert to source does only print in debug log level
#define INSERT_TO_SOURCE(message) DLOG(message)

std::string
get_real_path(const std::string& path, bool assert_on_error = true)
{
    char* path_real_path_char = realpath(path.c_str(), nullptr);
    if (path_real_path_char == nullptr) {
        if (assert_on_error) {
            ELOG("unable to resolve real path of " << path);
            llvm::outs().flush();
            assert(path_real_path_char != nullptr); //
        }
        return "";
    }
    std::string path_real_path(path_real_path_char);
    free(path_real_path_char);
    return path_real_path;
}

std::vector<std::string> all_include_paths = std::vector<std::string>();
void
initialize_all_include_paths(int argc, const char** argv)
{
    std::string include_prefix = "-I";
    for (int i = 0; i < argc; ++i) {
        std::string argv_as_string(argv[i]);
        if (argv_as_string.find(include_prefix) == 0) {
            std::string include_path = argv_as_string.substr(2);
            std::string real_path_include_path = get_real_path(include_path, false);
            if (real_path_include_path != "") {
                all_include_paths.push_back(include_path);
                all_include_paths.push_back(real_path_include_path);
            }
        }
    }
}

std::vector<std::regex> classes_to_skip = std::vector<std::regex>();
std::vector<std::regex> base_classes_to_skip = std::vector<std::regex>();
std::vector<std::regex> fields_to_skip = std::vector<std::regex>();
std::vector<std::tuple<std::string, std::regex, unsigned>> field_versions{};
std::vector<std::string> fields_types_to_skip = std::vector<std::string>();
std::vector<std::regex> fields_to_manual_serialize = std::vector<std::regex>();
std::vector<std::regex> classes_to_fwd_declare = std::vector<std::regex>();
std::vector<std::regex> files_to_skip = std::vector<std::regex>();
std::vector<std::string> lines_to_add_to_file = std::vector<std::string>();
std::string library_name = "";

void
initialize_data_from_config_file()
{
    std::string file_name = config_file.getValue();
    if (file_name == "") {
        return;
    }
    std::ifstream file_to_read(file_name);
    if (!file_to_read) {
        ELOG("unable to open cofig file! skipping...");

        return;
    }
    std::string read_line;
    std::smatch sm;
    int line_number = 0;
    std::regex class_ignore_regex("skip-class +([^ ]*) *(#.*)?");
    std::regex base_class_ignore_regex("skip-base-class +([^ ]*) *(#.*)?");
    std::regex class_development_ignore_regex("skip-class-development-stage +([^ ]*) *(#.*)?");
    std::regex field_ignore_regex("skip-field +([^ ]*) *(#.*)?");
    std::regex field_version_regex("versioned-field +([^ ]*) +([^ ]*) *(#.*)?");
    std::regex field_manual_regex("manual-field +([^ ]*) *(#.*)?");
    std::regex file_ignore_regex("skip-file +([^ ]*) *(#.*)?");
    std::regex fwd_declare_regex("fwd-declare +([^ ]*) *(#.*)?");
    std::regex commented_line_regex("\\s*#.*");
    std::regex code_segment_start_regex("%\\{\\s*(#.*)?");
    std::regex code_segment_end_regex("%\\}\\s*(#.*)?");
    std::regex lib_name_regex("library-name +(.*)?");
    bool is_code_to_add_section = false;
    while (std::getline(file_to_read, read_line)) {
        ++line_number;
        if (is_code_to_add_section) {
            if (std::regex_match(read_line, sm, code_segment_end_regex)) {
                is_code_to_add_section = false;
            } else {
                lines_to_add_to_file.push_back(read_line);
            }
            continue;
        }
        if (read_line == "" || std::regex_match(read_line, commented_line_regex)) {
            continue;
        }

        if (std::regex_match(read_line, sm, code_segment_start_regex)) {
            is_code_to_add_section = true;
            continue;
        }

        if (std::regex_match(read_line, sm, class_ignore_regex)) {
            classes_to_skip.emplace_back(sm[1].str());
        } else if (std::regex_match(read_line, sm, base_class_ignore_regex)) {
            base_classes_to_skip.emplace_back(sm[1].str());
        } else if (std::regex_match(read_line, sm, class_development_ignore_regex)) {
            fields_types_to_skip.emplace_back(sm[1].str());
        } else if (std::regex_match(read_line, sm, field_ignore_regex)) {
            fields_to_skip.emplace_back(sm[1].str());
        } else if (std::regex_match(read_line, sm, field_version_regex)) {
            std::string field_regex_str(sm[1].str());
            std::regex field_regex(field_regex_str);
            char* endptr;
            const char* ver_str = sm[2].str().c_str();

            unsigned field_ver = strtoul(ver_str, &endptr, 0);
            if (endptr == ver_str) {
                ELOG("line " << line_number << " versioned-field version (" << ver_str << ") is invalid\n");
                exit(1);
            }

            // validate uniqueness
            for (auto& field_ver : field_versions) {
                if (std::get<0>(field_ver) == field_regex_str) {
                    ELOG("line " << line_number << " versioned-field \"" << field_regex_str << "\" is defined multiple times\n");
                    exit(1);
                }
            }

            field_versions.emplace_back(std::make_tuple(field_regex_str, field_regex, field_ver));
        } else if (std::regex_match(read_line, sm, field_manual_regex)) {
            fields_to_manual_serialize.emplace_back(sm[1].str());
        } else if (std::regex_match(read_line, sm, fwd_declare_regex)) {
            classes_to_fwd_declare.emplace_back(sm[1].str());
        } else if (std::regex_match(read_line, sm, file_ignore_regex)) {
            std::string match = sm[1].str();
            if (match.find('/') == std::string::npos) {
                // got only file name, extending it with .*
                match = "([^ ]*/)?" + match;
            }
            files_to_skip.emplace_back(match);
        } else if (std::regex_match(read_line, sm, lib_name_regex)) {
            library_name = sm[1].str();
        } else {
            WLOG("line " << line_number << " in config file doesn't match any config rule! line content: " << read_line);
        }
    }

    if (library_name == "") {
        ELOG("Missing library-name directive\n");
        exit(1);
    }
}

static llvm::cl::OptionCategory ToolingSampleCategory("Tooling Sample");

static std::string UNKNOWN = "UNKNOWN";

enum outputMode { STDOUT, IN_PLACE, NO_OUT };

#ifdef DEBUG
// outputMode oMode = STDOUT;
outputMode oMode = NO_OUT;
#else
outputMode oMode = NO_OUT;
#endif

/* per field info */
struct field_info_t {
    std::string name;
    std::string manual_serialized_type;
    bool needs_local_copy = false;
    bool is_array = false;
    size_t array_size = 0;
    bool is_const_field = false;
    std::string field_type_stripped;
    std::string field_type_desugared;
    size_t serialization_chunk = 0;
    unsigned version;
};
/* per class info (fields, needed includes, etc) */
struct class_info_t {
    bool valid = true;
    std::string class_name;
    bool is_polymorphic = false;
    bool is_abstract = false;
    std::vector<std::string> contexts;
    bool is_virtual_inherited = false; // used for base classes info
    std::vector<field_info_t> fields;
    std::vector<class_info_t> base_classes; // base class names + is_virtual_inherited for each
    std::vector<class_info_t> required_serialization_classes;
    std::vector<class_info_t> additonal_required_polymorphic_register;
    std::vector<std::pair<class_info_t, class_info_t>> additonal_required_polymorphic_relation; // pairs of <base/derived>

    mutable std::string full_class_name; // used as cache to avoid recalculating it each time
    const std::string& get_full_class_name() const
    {
        if (full_class_name == "") {
            for (auto& context : contexts) {
                full_class_name += context + "::";
            }
            full_class_name += class_name;
        }
        return full_class_name;
    }
};

std::map<std::string, std::vector<class_info_t>> all_class_infos_per_file;
std::map<std::string, std::string> full_path_file_name_to_relative_path;
std::map<std::string, size_t> class_name_to_file_number;
std::vector<class_info_t> all_classes_to_fwd_declare;

void
add_class_info_to_map(llvm::StringRef file_name, const class_info_t& class_info)
{
    std::string full_file_name_path = get_real_path(file_name);
    all_class_infos_per_file[full_file_name_path].push_back(class_info);
    full_path_file_name_to_relative_path[full_file_name_path] = file_name;
}
void
add_class_info_to_map(SourceManager& SM, const SourceLocation& srcLoc, const class_info_t& class_info)
{
    add_class_info_to_map(SM.getFilename(srcLoc), class_info);
}
bool
is_class_already_loaded(llvm::StringRef file_name, llvm::StringRef class_name)
{
    std::string full_file_name_path = get_real_path(file_name);
    if (all_class_infos_per_file.count(full_file_name_path) == 0) {
        return false;
    }
    for (auto& class_info : all_class_infos_per_file[full_file_name_path]) {
        if (class_name == class_info.get_full_class_name()) {
            return true;
        }
    }
    return false;
}
bool
is_class_already_loaded(SourceManager& SM, const SourceLocation& srcLoc, llvm::StringRef class_name)
{
    return is_class_already_loaded(SM.getFilename(srcLoc), class_name);
}

/* helpers for handling parsed files */
// Will hold all unique hash values representing files included in compilation
// std::map<unsigned, std::pair<FileID, std::string>> ParsedFiles; // fid to file name
//
// bool IsFileInHash(const FileID& fid) {
//   return ParsedFiles.count(fid.getHashValue()) > 0;
// }
//
// bool IsFileInHash(SourceManager &SM, const SourceLocation& srcLoc) {
//   return IsFileInHash(SM.getFileID(srcLoc));
// }
//
// void AddFileToHash(const FileID& fid, const std::string& fileName) {
//   if (IsFileInHash(fid)) {
//     return;
//   }
//   ParsedFiles.emplace(fid.getHashValue(), std::make_pair(fid, fileName));
// }
//
// void AddFileToHash(SourceManager &SM, const SourceLocation& srcLoc) {
//   AddFileToHash(SM.getFileID(srcLoc), SM.getFilename(srcLoc));
// }
/* end of parsed files helpers */

void
replace_all(std::string& s, const std::string& search, const std::string& replace)
{
    for (size_t pos = 0;; pos += replace.length()) {
        // Locate the substring to replace
        pos = s.find(search, pos);
        if (pos == std::string::npos)
            break;
        // Replace by erasing and inserting
        s.erase(pos, search.length());
        s.insert(pos, replace);
    }
}

bool
StartsWith(const std::string& haystack, const std::string& needle)
{
    return needle.length() <= haystack.length() && haystack.compare(0, needle.length(), needle) == 0;
}

// macro to allow wasily dump file location of a parsed location
#define STR_LOC(loc) SM.getFilename(loc) << ":" << SM.getPresumedLineNumber(loc) << ":" << SM.getPresumedColumnNumber(loc)

bool
hasEnding(llvm::StringRef fullString, llvm::StringRef ending)
{
    if (fullString.size() >= ending.size()) {
        return (ending == fullString.substr(fullString.size() - ending.size(), ending.size()));
    } else {
        return false;
    }
}

// checks if a class or a field is marked as packed
bool
is_packed_declaration(clang::Decl* declaration)
{
    if (!declaration->hasAttrs()) {
        return false;
    }
    for (auto& attr : declaration->attrs()) {
        if (attr->getKind() == clang::attr::Kind::Packed) {
            return true;
        }
    }
    return false;
}

std::string
get_serialization_version_var_name()
{
    return "g_" + library_name + "_serialization_version";
}

// By implementing RecursiveASTVisitor, we can specify which AST nodes
// we're interested in by overriding relevant methods.

class MyASTVisitor : public RecursiveASTVisitor<MyASTVisitor>
{
public:
    explicit MyASTVisitor(Rewriter& R, ASTContext* ctx) : TheRewriter(R), _context(ctx)
    {
    }

    bool VisitDecl(Decl* s)
    {
        SourceManager& SM = TheRewriter.getSourceMgr();

        if (isa<CXXRecordDecl>(s)) {
            CXXRecordDecl* classDeclRecord = cast<CXXRecordDecl>(s)->getDefinition();

            // useful functions:
            // getEnclosingNamespaceContext()

            if (classDeclRecord == nullptr) {
                DLOG("got empty class decleration for class " << cast<CXXRecordDecl>(s)->getName());
                return true;
            }

            class_info_t class_info = get_class_info_for_type(classDeclRecord);
            if (!class_info.valid) {
                return true;
            }

            if (need_to_add_fwd_declaration(class_info)) {
                all_classes_to_fwd_declare.push_back(class_info);
            }

            // since we now may jumped to another file, need to check SkipSerialization again
            if (SkipSerialization(classDeclRecord)) {
                DLOG("skipping serialization for class " << class_info.class_name
                                                         << " (not in module dirs/file marked as skip/cpp file)");
                return true;
            }

            ClassTemplateDecl* class_as_template_decl = classDeclRecord->getDescribedClassTemplate();
            if (isa<ClassTemplateSpecializationDecl>(classDeclRecord) || class_as_template_decl != nullptr) {
                DLOG("skipping serialization for class " << class_info.class_name << " (template classes not supported)");
                return true;
            }
            // AddFileToHash(SM, classDeclRecord->getLocation());

            mSrcLoc = classDeclRecord->getLocStart();
            // mSrcLoc.dump(SM);
            if (is_class_already_loaded(SM, classDeclRecord->getLocation(), class_info.get_full_class_name())) {
                return true;
            }
            if (skip_class(class_info)) {
                DLOG("skipping serialization for class " << class_info.get_full_class_name() << " (class marked to be skipped)");
                return true;
            }
            // INSERT_TO_SOURCE("/* got class named: " << class_info.class_name << " */");
            // INSERT_TO_SOURCE("/* members:");
            for (FieldDecl* field : classDeclRecord->fields()) {
                // TODO X handle qualifiers
                if (skip_field(class_info, field->getName())) {
                    continue;
                }

                field_info_t field_info;
                field_info.name = field->getName();
                field_info.version = field_version(class_info, field->getName());

                QualType fieldQualType = field->getType();
                field_info.is_const_field = fieldQualType.isConstQualified();
                auto field_type = fieldQualType.getTypePtrOrNull();
                if (manual_serialize_field(class_info, field->getName())) {
                    // finding the save function in order to resolve the serialization type
                    std::string expected_method_name = std::string("save_") + std::string(field->getName());
                    field_info.needs_local_copy = false; // we shouldn't consider the original field's properties in this case
                    field_info.is_array = false;
                    field_info.field_type_stripped = "";
                    bool found = false;
                    for (auto method : classDeclRecord->methods()) {
                        if (method->getIdentifier() != nullptr && method->getName() == expected_method_name) {
                            found = true;
                            auto serialized_type = method->getReturnType();
                            add_dependent_types_to_class_info(
                                serialized_type.getNonReferenceType().getUnqualifiedType().getTypePtrOrNull(), class_info);
                            field_info.manual_serialized_type = get_type_name(serialized_type, true /* remove_qualifiers */);
                            if (field_info.manual_serialized_type == "" || field_info.manual_serialized_type == "void") {
                                ELOG("unable to resolve return type for function " << expected_method_name << " in class "
                                                                                   << class_info.get_full_class_name());
                                exit(1);
                            }
                            field_info.field_type_desugared = field_info.manual_serialized_type;
                            break;
                        }
                    }
                    if (!found) {
                        ELOG("field " << field->getName() << " in class " << class_info.get_full_class_name()
                                      << " was defined as manually-serailized, but function "
                                      << expected_method_name
                                      << " not found");
                        exit(1);
                    }
                } else {
                    bool skip_field = add_dependent_types_to_class_info(field_type, class_info);
                    if (!skip_field) {
                        continue;
                    }
                    if (is_packed_declaration(field) || is_packed_declaration(classDeclRecord)) {
                        field_info.needs_local_copy = true;
                        if (field_type->isArrayType()) {
                            assert(field_type->isConstantArrayType());
                            field_info.is_array = true;
                            auto element_type = field_type->getPointeeOrArrayElementType()->getUnqualifiedDesugaredType();
                            assert(isa<BuiltinType>(element_type));
                            field_info.field_type_stripped
                                = cast<BuiltinType>(element_type)->getName(PrintingPolicy(LangOptions()));
                            field_info.array_size = cast<ConstantArrayType>(field_type)->getSize().getRawData()[0];
                        } else {
                            field_info.field_type_stripped = fieldQualType.getUnqualifiedType().getAsString();
                        }
                    } else if (field->isBitField()) {
                        field_info.needs_local_copy = true;
                        field_info.field_type_stripped = fieldQualType.getUnqualifiedType().getAsString();
                    }
                    if (field_info.field_type_stripped == "_Bool") {
                        field_info.field_type_stripped
                            = "bool"; // clang desugars bool to _Bool, but gcc doesn't always recognize _Bool
                    }
                    field_info.field_type_desugared = get_type_name(fieldQualType, true);

                    // std::string typeAsString;
                    while (true) {
                        const Type* fieldType = fieldQualType.getTypePtrOrNull();
                        if (fieldType == nullptr) {
                            // typeAsString += "null type";
                            break;
                        }
                        if (isa<TypedefType>(fieldType)) {
                            // typeAsString += get_typedef_desugar_str(cast<TypedefType>(fieldType));
                            fieldType = fieldType->getUnqualifiedDesugaredType();
                        }
                        if (fieldType->isBuiltinType()) {
                            // assert(isa<BuiltinType>(fieldType));
                            // auto bit = cast<BuiltinType>(fieldType);
                            // auto nameAsStr = bit->getName(PrintingPolicy(LangOptions()));
                            // typeAsString += std::string("builtin type ") + std::string(nameAsStr);
                            break;
                        }
                        if (fieldType->isAnyPointerType()) {
                            // typeAsString += "pointer to ";
                            // fieldQualType = fieldType->getPointeeType();
                            break;
                        }
                        if (fieldType->isReferenceType()) {
                            ELOG("Reference members are not supported! class: " << class_info.get_full_class_name() << ", field: "
                                                                                << field->getName()
                                                                                << ", in: "
                                                                                << STR_LOC(field->getLocation()));
                            exit(1);
                        }
                        CXXRecordDecl* fieldTypeAsCxxDecl = fieldType->getAsCXXRecordDecl();
                        if (fieldTypeAsCxxDecl != nullptr) {
                            // typeAsString += fieldTypeAsCxxDecl->getName();
                            break;
                        }

                        // typeAsString += "unknown type, see dump";
                        if (program_log_level <= LOG_LEVEL_DEBUG) {
                            // fieldType->dump(llvm::outs());
                        }
                        break;
                    }
                }

                if (field_info.field_type_desugared.find("weak_ptr", 0) != std::string::npos) {
                    field_info.serialization_chunk = 1;
                }

                class_info.fields.push_back(field_info);
                // INSERT_TO_SOURCE("    field " + field->getName() + " of type " + typeAsString);
            }
            // INSERT_TO_SOURCE("*/");

            add_base_classes_dependencies(class_info_t(), classDeclRecord, true /* is_main_class */, class_info);

            // sorting the fields so the weak_ptrs are serialized later in the code.
            std::stable_sort(class_info.fields.begin(), class_info.fields.end(), [](const field_info_t& a, const field_info_t& b) {
                return a.serialization_chunk < b.serialization_chunk;
            });

            DLOG("adding info for class " << class_info.get_full_class_name());
            llvm::outs().flush();
            add_class_info_to_map(SM, classDeclRecord->getLocation(), class_info);
        }
        return true;
    }

private:
    QualType get_unqualified_desugared_type(QualType class_qual_type)
    {
        const Type* base_class_type = class_qual_type.getTypePtrOrNull();
        while (true) {
            class_qual_type = class_qual_type.getDesugaredType(*_context);
            base_class_type = base_class_type->getUnqualifiedDesugaredType();
            if (isa<ElaboratedType>(base_class_type)) {
                auto base_class_elaborated = cast<ElaboratedType>(base_class_type);
                class_qual_type = base_class_elaborated->getNamedType();
                base_class_type = class_qual_type.getTypePtrOrNull();
                continue;
            }
            break;
        }
        return class_qual_type;
    }

    bool add_base_classes_dependencies(class_info_t current_class_info,
                                       CXXRecordDecl* classDeclRecord,
                                       bool is_main_class,
                                       class_info_t& inout_class_info)
    {
        std::set<std::string> temp_handled_classes;
        return add_base_classes_dependencies(
            current_class_info, classDeclRecord, is_main_class, temp_handled_classes, inout_class_info);
    }

    bool add_base_classes_dependencies(class_info_t current_class_info,
                                       CXXRecordDecl* classDeclRecord,
                                       bool is_main_class,
                                       std::set<std::string>& handled_classes,
                                       class_info_t& inout_class_info)
    {
        if (!is_main_class) {
            // need to resolve/add polymorphic relations for template classes
            // we assume that the class here is template
            if (!current_class_info.is_polymorphic) {
                return true;
            }
            inout_class_info.additonal_required_polymorphic_register.push_back(current_class_info);
        }
        for (auto& base_class : classDeclRecord->bases()) {
            QualType base_class_qual_type = get_unqualified_desugared_type(base_class.getType());
            const Type* base_class_type = base_class_qual_type.getTypePtrOrNull();

            bool status = add_dependent_types_to_class_info(base_class_type, handled_classes, inout_class_info);
            if (!status) {
                return false;
            }
            CXXRecordDecl* base_class_as_cxx_decl = base_class_type->getAsCXXRecordDecl();
            class_info_t base_class_info = get_class_info_for_type(base_class_as_cxx_decl);
            if (!base_class_info.valid) {
                DLOG("error in base class for class " << inout_class_info.get_full_class_name());
                return true;
            }
            if (skip_base_class(base_class_info)) {
                continue;
            }
            if (isa<ClassTemplateSpecializationDecl>(base_class_as_cxx_decl)) {
                adjust_class_name_to_contain_template_params(base_class_qual_type, base_class_info);
            }
            if (is_main_class) {
                base_class_info.is_virtual_inherited = base_class.isVirtual();
                inout_class_info.base_classes.push_back(base_class_info);
            } else {
                if (base_class_info.is_polymorphic) {
                    inout_class_info.additonal_required_polymorphic_relation.push_back(
                        std::make_pair(base_class_info, current_class_info));
                }
            }
        }
        return true;
    }

    bool add_dependent_types_to_class_info_from_template_arg(const TemplateArgument& template_arg,
                                                             std::set<std::string>& handled_classes,
                                                             class_info_t& inout_class_info)
    {
        auto arg_kind = template_arg.getKind();

        switch (arg_kind) {
        case (TemplateArgument::ArgKind::Type): {
            bool result
                = add_dependent_types_to_class_info(template_arg.getAsType().getTypePtrOrNull(), handled_classes, inout_class_info);
            if (!result) {
                return result;
            }
            break;
        }
        case (TemplateArgument::ArgKind::Pack): {
            for (auto& template_arg_in_pack : template_arg.pack_elements()) {
                bool result
                    = add_dependent_types_to_class_info_from_template_arg(template_arg_in_pack, handled_classes, inout_class_info);
                if (!result) {
                    return result;
                }
            }
            break;
        }
        default:
            // nothing to do here
            break;
        }
        return true;
    }
    bool add_dependent_types_to_class_info_from_template_instance(const Type* type_to_add_as_type,
                                                                  ClassTemplateSpecializationDecl* type_to_add,
                                                                  std::set<std::string>& handled_classes,
                                                                  class_info_t& inout_class_info)
    {
        class_info_t class_info = get_class_info_for_type(type_to_add);
        adjust_class_name_to_contain_template_params(QualType(type_to_add_as_type, 0), class_info);
        if (handled_classes.count(class_info.get_full_class_name()) > 0) {
            return true;
        }
        handled_classes.insert(class_info.get_full_class_name());
        bool result
            = add_base_classes_dependencies(class_info, type_to_add, false /* is_main_type */, handled_classes, inout_class_info);
        if (!result) {
            return result;
        }
        for (auto& template_arg : type_to_add->getTemplateInstantiationArgs().asArray()) {
            result = add_dependent_types_to_class_info_from_template_arg(template_arg, handled_classes, inout_class_info);
            if (!result) {
                return result;
            }
        }
        return true;
    }

    bool add_dependent_types_to_class_info(const Type* type_to_add, class_info_t& inout_class_info)
    {
        std::set<std::string> temp_handled_classes;
        return add_dependent_types_to_class_info(type_to_add, temp_handled_classes, inout_class_info);
    }
    // returns false if the field is dependent on class that should be ignored (developement stage only!)
    bool add_dependent_types_to_class_info(const Type* type_to_add,
                                           std::set<std::string>& handled_classes,
                                           class_info_t& inout_class_info)
    {
        if (type_to_add == nullptr) {
            return true; // no fwd-declarations needed here
        }
        if (isa<ElaboratedType>(type_to_add)) {
            auto class_elaborated = cast<ElaboratedType>(type_to_add);
            auto class_qual_type = class_elaborated->getNamedType();
            type_to_add = class_qual_type.getTypePtrOrNull();
        }
        if (isa<TypedefType>(type_to_add)) {
            type_to_add = type_to_add->getUnqualifiedDesugaredType();
        }
        if (type_to_add->isBuiltinType()) {
            return true; // built-in types are already supported natively by cereal
        }
        if (type_to_add->isAnyPointerType() || type_to_add->isArrayType()) {
            return add_dependent_types_to_class_info(
                type_to_add->getPointeeOrArrayElementType(), handled_classes, inout_class_info);
        }
        CXXRecordDecl* type_to_add_as_CxxDecl = type_to_add->getAsCXXRecordDecl();
        if (type_to_add_as_CxxDecl == nullptr) {
            return true; // non-standard type, no need for fwd_declare it
        }
        if (type_to_add_as_CxxDecl->getDefinition() != nullptr) {
            type_to_add_as_CxxDecl = type_to_add_as_CxxDecl->getDefinition();
        }

        class_info_t class_info_to_add = get_class_info_for_type(type_to_add_as_CxxDecl);
        if (skip_field_based_on_class_type(class_info_to_add)) {
            return false;
        }
        if (isa<ClassTemplateSpecializationDecl>(type_to_add_as_CxxDecl)) {
            return add_dependent_types_to_class_info_from_template_instance(
                type_to_add, cast<ClassTemplateSpecializationDecl>(type_to_add_as_CxxDecl), handled_classes, inout_class_info);
        }
        if (isa<TemplateSpecializationType>(type_to_add)) {
            return true; // templates are not handled by the tool
        }
        if (!skip_class(class_info_to_add)) {
            // this class will not be defined in current module, need to forward declare it
            inout_class_info.required_serialization_classes.push_back(class_info_to_add);
        }
        return true;
    }

    void adjust_class_name_to_contain_template_params(const QualType& class_qual_type, class_info_t& class_info)
    {
        auto printingPolicy = clang::PrintingPolicy(LangOptions());
        printingPolicy.SuppressUnwrittenScope = false;
        printingPolicy.SuppressScope = false;
        // replacing class name to contain template params if exist
        std::string class_name_with_template_params = class_qual_type.getAsString(printingPolicy);
        // removing leading context and/or class/struct decaration
        size_t pos = class_name_with_template_params.find(class_info.class_name);
        if (pos != std::string::npos && pos > 0) {
            class_name_with_template_params.erase(0, pos);
        }
        class_info.class_name = class_name_with_template_params;
        class_info.full_class_name = ""; // clearing full class name cache so it will be recreated
    }

    class_info_t get_class_info_for_type(CXXRecordDecl* class_decl)
    {
        class_info_t result;
        result.class_name = class_decl->getName();
        if (auto class_def = class_decl->getDefinition()) {
            result.is_polymorphic = class_def->isPolymorphic();
            result.is_abstract = class_def->isAbstract();
        }
        if (!get_context_of_declaration(class_decl, result.contexts)) {
            result.valid = false;
        }
        return result;
    }

    bool SkipSerialization(Decl* d)
    {
        SourceManager& SM = TheRewriter.getSourceMgr();
        SourceLocation srcLoc = d->getLocation();
        if (srcLoc.isInvalid()) {
            return true;
        }
        llvm::StringRef fullFilePath = SM.getFilename(srcLoc);
        if (fullFilePath == "") {
            return true;
        }
        if (hasEnding(fullFilePath, ".cpp")) {
            return true;
        }

        if (skip_file(fullFilePath)) {
            return true;
        }

        if (is_path_in_folders(fullFilePath, module_dirs)) {
            return false;
        }

        return true;
    }

    std::string get_type_name(QualType qual_type, bool remove_qualifiers)
    {
        std::string result;
        if (remove_qualifiers) {
            qual_type = qual_type.getNonReferenceType().getUnqualifiedType();
        }
        const Type* fieldType = qual_type.getTypePtrOrNull();
        if (fieldType == nullptr) {
            return "void";
        }
        while (true) {
            qual_type = qual_type.getDesugaredType(*_context);
            fieldType = fieldType->getUnqualifiedDesugaredType();
            if (isa<ElaboratedType>(fieldType)) {
                auto class_elaborated = cast<ElaboratedType>(fieldType);
                qual_type = class_elaborated->getNamedType();
                fieldType = qual_type.getTypePtrOrNull();
                continue;
            }
            break;
        }
        if (fieldType->isArrayType()) {
            fieldType = fieldType->getPointeeOrArrayElementType()->getUnqualifiedDesugaredType();
        }
        if (fieldType->isBuiltinType()) {
            assert(isa<BuiltinType>(fieldType));
            auto bit = cast<BuiltinType>(fieldType);
            auto nameAsStr = bit->getName(PrintingPolicy(LangOptions()));
            return std::string(nameAsStr);
        }
        if (fieldType->isIntegralOrEnumerationType()) {
            // TODO get enum name!
            return "";
        }
        if (fieldType->isAnyPointerType()) {
            result = get_type_name(fieldType->getPointeeType(), remove_qualifiers);
            result += "*";
            return result;
        }

        CXXRecordDecl* fieldTypeAsCxxDecl = fieldType->getAsCXXRecordDecl();
        if (fieldTypeAsCxxDecl == nullptr) {
            ELOG("unable to resolve type!");
            if (program_log_level <= LOG_LEVEL_ERROR) {
                fieldType->dump(llvm::outs());
            }
            return "";
        }

        class_info_t class_info = get_class_info_for_type(fieldTypeAsCxxDecl);
        if (!class_info.valid) {
            ELOG("error in type resolving for class " << class_info.get_full_class_name());
            return "";
        }

        if (isa<ClassTemplateSpecializationDecl>(fieldTypeAsCxxDecl)) {
            adjust_class_name_to_contain_template_params(qual_type, class_info);
        }
        return class_info.get_full_class_name();
    }

    bool skip_field_based_on_class_type(const class_info_t& class_info)
    {
        const std::string& full_class_name = class_info.get_full_class_name();
        for (auto& class_match : fields_types_to_skip) {
            if (full_class_name == class_match) {
                return true;
            }
        }
        return false;
    }

    bool need_to_add_fwd_declaration(const class_info_t& class_info)
    {
        bool found = false;
        const std::string& full_class_name = class_info.get_full_class_name();
        for (auto& class_match : classes_to_fwd_declare) {
            if (std::regex_match(full_class_name, class_match)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return false;
        }
        return !skip_class(class_info); // skipped classes shouldn't be fwd-declared
    }

    bool skip_class(const class_info_t& class_info)
    {
        const std::string& full_class_name = class_info.get_full_class_name();
        for (auto& class_match : classes_to_skip) {
            if (std::regex_match(full_class_name, class_match)) {
                return true;
            }
        }
        return skip_field_based_on_class_type(class_info);
    }

    bool skip_base_class(const class_info_t& class_info)
    {
        const std::string& full_class_name = class_info.get_full_class_name();
        for (auto& class_match : base_classes_to_skip) {
            if (std::regex_match(full_class_name, class_match)) {
                return true;
            }
        }
        return skip_field_based_on_class_type(class_info);
    }

    bool skip_file(const std::string& file_name)
    {
        if (files_to_skip.size() == 0) {
            return false;
        }
        for (auto& file_match : files_to_skip) {
            if (std::regex_match(file_name, file_match)) {
                return true;
            }
        }
        return false;
    }

    bool skip_field(const class_info_t& class_info, llvm::StringRef field_name)
    {
        if (fields_to_skip.size() == 0) {
            return false;
        }
        std::string full_field_name = class_info.get_full_class_name() + "::" + field_name.str();
        for (auto& field_match : fields_to_skip) {
            if (std::regex_match(full_field_name, field_match)) {
                return true;
            }
        }
        return false;
    }

    unsigned field_version(const class_info_t& class_info, llvm::StringRef field_name)
    {
        if (field_versions.size() == 0) {
            return 1;
        }

        std::string full_field_name = class_info.get_full_class_name() + "::" + field_name.str();
        for (auto& field_ver : field_versions) {
            auto& field_match = std::get<1>(field_ver);
            if (std::regex_match(full_field_name, field_match)) {
                return std::get<2>(field_ver);
            }
        }
        return false;
    }

    bool manual_serialize_field(const class_info_t& class_info, llvm::StringRef field_name)
    {
        if (fields_to_manual_serialize.size() == 0) {
            return false;
        }
        std::string full_field_name = class_info.get_full_class_name() + "::" + field_name.str();
        for (auto& field_match : fields_to_manual_serialize) {
            if (std::regex_match(full_field_name, field_match)) {
                return true;
            }
        }
        return false;
    }
    bool is_path_in_folders(const std::string& path, const std::vector<std::string>& folders)
    {
        std::string path_real_path = get_real_path(path);
        std::string adjusted_path = path;
        while (StartsWith(adjusted_path, "./")) {
            // removing "./" in beginning
            adjusted_path = adjusted_path.substr(2);
        }
        for (auto& folder : folders) {
            std::string folder_real_path = get_real_path(folder, false);
            if (folder_real_path == "") {
                continue;
            }
            if (StartsWith(adjusted_path, folder)) {
                return true;
            }
            if (StartsWith(path_real_path, folder_real_path)) {
                return true;
            }
        }
        return false;
    }
    bool get_context_of_declaration(Decl* s, std::vector<std::string>& out_contexts)
    {
        if (s == nullptr) {
            return true;
        }
        SourceManager& SM = TheRewriter.getSourceMgr();
        if (s->getParentFunctionOrMethod() != nullptr) {
            FunctionDecl* function = cast<FunctionDecl>(s->getParentFunctionOrMethod());
            DLOG("classes defined inside functions are not supported!! (function name: " << function->getName() << ", at "
                                                                                         << STR_LOC(function->getLocation())
                                                                                         << ")");
            llvm::outs().flush();
            return false;
        }
        DeclContext* context = s->getDeclContext();
        if (context == nullptr) {
            return true;
        }
        if (!isa<Decl>(context)) {
            ELOG("unknown context...");
            llvm::errs().flush();
            context->dumpDeclContext();
            return false;
        }
        if (isa<NamedDecl>(context)) {
            NamedDecl* context_as_named_context = cast<NamedDecl>(context);
            if (!isa<NamespaceDecl>(context) && !isa<CXXRecordDecl>(context)) {
                ELOG("context of declaration is not supported! context name: "
                     << context_as_named_context->getName()
                     << ", context type: "
                     << context_as_named_context->getDeclKindName()
                     << " (defined at: "
                     << context_as_named_context->getLocation().printToString(TheRewriter.getSourceMgr())
                     << ")");
                llvm::errs().flush();
                return false;
            }
            out_contexts.insert(out_contexts.begin(), context_as_named_context->getName());
        }
        return get_context_of_declaration(cast<Decl>(context), out_contexts);
    }

    std::string get_typedef_desugar_str(const TypedefType* field_type)
    {

        std::string result;
        if (!field_type->isSugared()) {
            return result;
        }
        result = "(typedef ";
        while (field_type != nullptr && field_type->isSugared()) {
            result += std::string(field_type->getDecl()->getName()) + "->";
            const Type* field_type_regular = field_type->desugar().getTypePtrOrNull();
            if (isa<TypedefType>(field_type_regular)) {
                field_type = cast<TypedefType>(field_type_regular);
            } else {
                field_type = nullptr;
            }
        }
        result += ")";
        return result;
    }

private:
    Rewriter& TheRewriter;
    ASTContext* _context;
    /*source location of the condition expression, used for debugging*/
    SourceLocation mSrcLoc;
};

// Implementation of the ASTConsumer interface for reading an AST produced
// by the Clang parser.
class MyASTConsumer : public ASTConsumer
{
public:
    explicit MyASTConsumer(ASTContext* context, Rewriter& R) : Visitor(R, context)
    {
    }

    // Override the method that gets called for each parsed top-level
    // declaration.
    bool HandleTopLevelDecl(DeclGroupRef DR) override
    {
        for (DeclGroupRef::iterator b = DR.begin(), e = DR.end(); b != e; ++b) {
            // Traverse the declaration using our AST visitor.
            Visitor.TraverseDecl(*b);

            // Dump AST
            // (*b)->dump();
        }
        return true;
    }

private:
    MyASTVisitor Visitor;
};

// For each source file provided to the tool, a new FrontendAction is created.
class MyFrontendAction : public ASTFrontendAction
{
public:
    MyFrontendAction()
    {
    }

    void EndSourceFileAction() override
    {
        SourceManager& SM = TheRewriter.getSourceMgr();
        llvm::StringRef OrigFile = SM.getFileEntryForID(SM.getMainFileID())->getName();
        DLOG("** EndSourceFileAction for: " << OrigFile);
        llvm::errs().flush();
        bool overwriteErr = false;
        switch (oMode) {
        case IN_PLACE:
            overwriteErr = TheRewriter.overwriteChangedFiles();
            if (overwriteErr) {
                ELOG("Error overwriting file!");
                llvm::outs().flush();
            }
            break;
        // case STDOUT:
        //  for (auto& fileDesc : ParsedFiles) {
        //    llvm::outs() << "File: " << fileDesc.second.second << "\n";
        //    llvm::outs().flush();
        //  TheRewriter.getEditBuffer(fileDesc.second.first).write(llvm::outs());
        //  }
        //  break;
        case NO_OUT:
            break;
        default:
            ELOG("invalid output mode specified");
            llvm::errs().flush();
        }
    }

    std::unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance& CI, StringRef file) override
    {
        DLOG("** Creating AST consumer for: " << file);
        llvm::errs().flush();
        TheRewriter.setSourceMgr(CI.getSourceManager(), CI.getLangOpts());
        return llvm::make_unique<MyASTConsumer>(&CI.getASTContext(), TheRewriter);
    }

private:
    Rewriter TheRewriter;
};

void
printUsage()
{
    PLOG("Invocation: macrogen -extra-arg=-Ipath/to/clang/includes -extra-arg=-Wno-error FILE");
    PLOG("Example: ./macrogen -extra-arg=-I/home/user/tools/llvm/tools/clang/7.0.1/include main.cpp -- -n");
}

std::string
adjust_file_path(const std::string& file_path, bool full_path = false)
{
    std::string current_path = full_path ? get_real_path(file_path) : full_path_file_name_to_relative_path[file_path];
    while (StartsWith(current_path, "./")) {
        current_path = current_path.substr(2);
    }
    // Search for the substring in string
    for (auto& include_path : all_include_paths) {
        size_t pos = current_path.find(include_path);
        if (pos == 0) {
            // If found then erase it from string
            std::string result = current_path;
            result.erase(0, include_path.length());
            if (result[0] == '/') {
                result.erase(0, 1);
            }
            return result;
        }
    }
    if (full_path) {
        return full_path_file_name_to_relative_path[file_path];
    } else {
        return adjust_file_path(file_path, true);
    }
}

void
map_classes_to_files()
{
    // first count num of classes and fields
    constexpr size_t constant_num_of_lines_per_class = 5;
    size_t num_of_lines = 0;
    for (auto& file_and_classes_info : all_class_infos_per_file) {
        for (auto& class_info : file_and_classes_info.second) {
            num_of_lines += class_info.fields.size();
            // per class add constant 5 lines
            num_of_lines += constant_num_of_lines_per_class;
        }
    }

    size_t num_of_lines_per_file = (num_of_lines + num_of_generated_files.getValue() - 1) / num_of_generated_files.getValue();
    size_t current_line_counter = 0;
    size_t current_file_index = 1;
    for (auto& file_and_classes_info : all_class_infos_per_file) {
        for (auto& class_info : file_and_classes_info.second) {
            // first adding the class
            assert(current_file_index <= num_of_generated_files.getValue());
            class_name_to_file_number[class_info.get_full_class_name()] = current_file_index;
            current_line_counter += class_info.fields.size();
            current_line_counter += constant_num_of_lines_per_class;
            if (current_line_counter > num_of_lines_per_file) {
                // need to start next file
                current_line_counter -= num_of_lines_per_file;
                current_file_index++;
            }
        }
    }
}

void
dump_fwd_declaration_to_file(std::ofstream& out_file, const std::string& class_name)
{
    out_file << "template <class Archive> void save(Archive&, const " << class_name << "&);\n";
    out_file << "template <class Archive> void load(Archive&, " << class_name << "&);\n\n";
}

std::string
generate_additional_fwd_declarations_file()
{
    if (all_classes_to_fwd_declare.size() == 0) {
        return "";
    }
    std::string file_name = output_file_path.getValue();
    file_name = std::regex_replace(file_name, std::regex("%"), "fwd_declarations");
    file_name = std::regex_replace(file_name, std::regex("\\.cpp$"), ".h");
    std::ofstream generated_file(file_name);

    generated_file << "namespace cereal {\n\n";

    for (auto& class_info : all_classes_to_fwd_declare) {
        dump_fwd_declaration_to_file(generated_file, class_info.get_full_class_name());
    }

    generated_file << "}\n\n";

    return file_name;
}

void
create_cpp_file_for_cereal()
{
    map_classes_to_files();
    auto additional_fwd_declaration_file_name = generate_additional_fwd_declarations_file();
    for (size_t file_index = 1; file_index <= num_of_generated_files.getValue(); ++file_index) {
        std::string file_name = output_file_path.getValue();
        file_name = std::regex_replace(file_name, std::regex("%"), std::to_string(file_index));
        std::ofstream generated_file(file_name);
        std::vector<std::string> function_types = {"save", "load"};
        std::map<std::string, std::string> param_const;
        param_const["save"] = "const ";
        param_const["load"] = "";
        // adding the template instances
        std::map<std::string, std::vector<std::string>> archive_types;
        archive_types["save"] = {"cereal_output_archive_class"};
        archive_types["load"] = {"cereal_input_archive_class"};

        generated_file << "#define AUTO_SERIALIZE_CODE\n";
        generated_file << "#include \"common/cereal_utils.h\"\n\n";

        generated_file << "#ifdef CEREAL_DISABLE_OPTIMIZATION\n";
        generated_file << "// Disable optimizations as clang, GCC choke on this file in -O3 mode.\n";
        generated_file << "#ifdef __GNUC__\n";
        generated_file << "    #ifdef __clang__\n";
        generated_file << "        #pragma clang optimize off\n";
        generated_file << "    #else\n";
        generated_file << "        #pragma GCC optimize (\"O0\")\n";
        generated_file << "    #endif\n";
        generated_file << "#endif\n";
        generated_file << "#endif\n";

        generated_file << "#if CEREAL_MODE == CEREAL_MODE_BINARY\n";
        generated_file << "#include <cereal/archives/binary.hpp>\n";
        generated_file << "#elif CEREAL_MODE == CEREAL_MODE_JSON\n";
        generated_file << "#include <cereal/archives/json.hpp>\n";
        generated_file << "#elif CEREAL_MODE == CEREAL_MODE_XML\n";
        generated_file << "#include <cereal/archives/xml.hpp>\n";
        generated_file << "#endif\n";

        generated_file << "#include <cereal/types/array.hpp>\n";
        generated_file << "#include <cereal/types/atomic.hpp>\n";
        generated_file << "#include <cereal/types/base_class.hpp>\n";
        generated_file << "#include <cereal/types/bitset.hpp>\n";
        // generated_file << "#include <cereal/types/boost_variant.hpp>\n";
        generated_file << "#include <cereal/types/chrono.hpp>\n";
        // generated_file << "#include <cereal/types/common.hpp>\n";
        // generated_file << "#include <cereal/types/complex.hpp>\n";
        // generated_file << "#include <cereal/types/deque.hpp>\n";
        generated_file << "#include <cereal/types/forward_list.hpp>\n";
        generated_file << "#include <cereal/types/functional.hpp>\n";
        generated_file << "#include <cereal/types/list.hpp>\n";
        generated_file << "#include <cereal/types/map.hpp>\n";
        generated_file << "#include <cereal/types/memory.hpp>\n";
        // generated_file << "#include <cereal/types/optional.hpp>\n";
        generated_file << "#include <cereal/types/polymorphic.hpp>\n";
        generated_file << "#include <cereal/types/queue.hpp>\n";
        generated_file << "#include <cereal/types/set.hpp>\n";
        generated_file << "#include <cereal/types/stack.hpp>\n";
        generated_file << "#include <cereal/types/string.hpp>\n";
        generated_file << "#include <cereal/types/tuple.hpp>\n";
        generated_file << "#include <cereal/types/unordered_map.hpp>\n";
        generated_file << "#include <cereal/types/unordered_set.hpp>\n";
        generated_file << "#include <cereal/types/utility.hpp>\n";
        // generated_file << "#include <cereal/types/valarray.hpp>\n";
        // generated_file << "#include <cereal/types/variant.hpp>\n";
        generated_file << "#include <cereal/types/vector.hpp>\n\n";

        for (auto& file_and_classes_info : all_class_infos_per_file) {
            generated_file << "#include \"" << adjust_file_path(file_and_classes_info.first) << "\"\n";
        }

        generated_file << "\n";

        generated_file << "template <class T>\n";
        generated_file << "static T&\n";
        generated_file << "cereal_gen_remove_const(const T& t)\n";
        generated_file << "{\n";
        generated_file << "    return const_cast<T&>(t);\n";
        generated_file << "}\n\n";

        generated_file << "#define CEREAL_GEN_COPY_ARRAY(from, to, size) \\\n";
        generated_file << "for (size_t i = 0; i < size; ++i) {\\\n";
        generated_file << "    to[i] = from[i];\\\n";
        generated_file << "}\n\n";

        generated_file << "#define CEREAL_GEN_COMMA() ,\n";

        for (auto& line_to_add : lines_to_add_to_file) {
            generated_file << line_to_add << "\n";
        }

        if (additional_fwd_declaration_file_name != "") {
            generated_file << "#include \"" << adjust_file_path(additional_fwd_declaration_file_name) << "\"\n";
        }

        generated_file << "\n";

        generated_file << "namespace cereal {\n\n";

        // Serialization version and its setter function
        std::string ver_var_name = get_serialization_version_var_name();
        if (file_index == 1) {
            generated_file << "unsigned " << ver_var_name << " = 1;\n";
            generated_file << "void cereal_gen_set_serialization_version_" << library_name
                           << "(unsigned int version) {" + ver_var_name + " = version;}\n";
        } else {
            generated_file << "extern unsigned " << ver_var_name << ";\n";
        }

        generated_file << "\n";
        std::set<std::string> fwd_declaration_classes;

        for (auto& file_and_classes_info : all_class_infos_per_file) {
            for (auto& class_info : file_and_classes_info.second) {
                if (class_name_to_file_number[class_info.get_full_class_name()] != file_index) {
                    // no need to add fwd declarations for this class
                    continue;
                }
                for (auto& fwd_decl_type : class_info.required_serialization_classes) {
                    if (class_name_to_file_number.count(fwd_decl_type.get_full_class_name()) == 0
                        || class_name_to_file_number[fwd_decl_type.get_full_class_name()] != file_index) {
                        fwd_declaration_classes.insert(fwd_decl_type.get_full_class_name());
                    }
                }
            }
        }
        for (auto& class_name : fwd_declaration_classes) {
            dump_fwd_declaration_to_file(generated_file, class_name);
        }

        std::vector<StringRef> polymorphic_classes;
        std::vector<StringRef> polymorphic_classes_to_force_serialize;
        std::vector<std::pair<std::string, std::string>> polymorphic_relations;
        for (auto& file_and_classes_info : all_class_infos_per_file) {
            for (auto& class_info : file_and_classes_info.second) {
                if (class_name_to_file_number[class_info.get_full_class_name()] != file_index) {
                    continue;
                }
                const std::string& context_of_declaration = class_info.get_full_class_name();
                // generating the serialize function definition
                generated_file << "template<>\n";
                generated_file << "class serializer_class<" << context_of_declaration << "> {\n";
                generated_file << "public:\n";
                for (auto& function_type : function_types) {
                    generated_file << "    template <class Archive>\n";
                    generated_file << "    static void\n";
                    generated_file << "    do_" << function_type << "(Archive& archive, " << param_const[function_type]
                                   << context_of_declaration << "& m) {\n";
                    // creating local_variables for manually serialized fields
                    for (auto& field : class_info.fields) {
                        if (field.manual_serialized_type != "" && function_type == "load") {
                            generated_file << "        " << field.manual_serialized_type << " m_" << field.name << ";\n";
                        } else if (field.needs_local_copy) {
                            generated_file << "        " << field.field_type_stripped << " m_" << field.name;
                            if (field.is_array) {
                                generated_file << "[" << field.array_size << "]";
                            }
                            if (function_type == "save" && !field.is_array) {
                                generated_file << " = m." << field.name;
                            }
                            generated_file << ";\n";
                            if (function_type == "save" && field.is_array) {
                                generated_file << "        CEREAL_GEN_COPY_ARRAY(m." << field.name << ", m_" << field.name << ", "
                                               << field.array_size << ")\n";
                            }
                        }
                    }
                    if (class_info.fields.size() > 0) {
                        for (auto& field : class_info.fields) {
                            std::string object_name_to_serialize = "m." + field.name;
                            if (field.manual_serialized_type != "") {
                                if (function_type == "load") {
                                    object_name_to_serialize = "m_" + field.name;
                                } else {
                                    object_name_to_serialize = "m.save_" + field.name + "()";
                                }
                            } else if (field.needs_local_copy) {
                                object_name_to_serialize = "m_" + field.name;
                            } else if (field.is_const_field) {
                                object_name_to_serialize = "cereal_gen_remove_const(" + object_name_to_serialize + ")";
                            }

                            if (field.version > 1) {
                                auto g_ver = get_serialization_version_var_name();
                                generated_file << "        if (" << g_ver << " >= " << field.version << ") {\n";
                            }
                            generated_file << "            archive(::cereal::make_nvp(\"" << field.name << "\", "
                                           << object_name_to_serialize << "));\n";

                            if (field.version > 1) {
                                generated_file << "        };\n";
                            }
                        }
                    }
                    if (function_type == "load") {
                        // adding activation to manual loading the code
                        for (auto& field : class_info.fields) {
                            if (field.manual_serialized_type != "") {
                                generated_file << "        m.load_" << field.name << "(m_" << field.name << ");\n";
                            } else if (field.needs_local_copy) {
                                if (field.version > 1) {
                                    auto g_ver = get_serialization_version_var_name();
                                    generated_file << "        if (" << g_ver << " >= " << field.version << ") {\n";
                                }

                                std::string object_name_to_serialize = "m." + field.name;
                                if (field.is_const_field) {
                                    object_name_to_serialize = "cereal_gen_remove_const(" + object_name_to_serialize + ")";
                                }
                                if (field.is_array) {
                                    generated_file << "        CEREAL_GEN_COPY_ARRAY(m_" << field.name << ", m." << field.name
                                                   << ", " << field.array_size << ")\n";
                                } else {
                                    generated_file << "        " << object_name_to_serialize << " = m_" << field.name << ";\n";
                                }

                                if (field.version > 1) {
                                    generated_file << "        };\n";
                                }
                            }
                        }
                    }
                    generated_file << "    }\n";
                }
                generated_file << "};\n";

                for (auto& function_type : function_types) {
                    generated_file << "template <class Archive>\n";
                    generated_file << "void\n";
                    generated_file << function_type << "(Archive& archive, " << param_const[function_type] << context_of_declaration
                                   << "& m)\n";
                    generated_file << "{\n";
                    if (class_info.base_classes.size() > 0) {
                        generated_file << "    archive(";
                        std::string separator = "";
                        for (auto& base_class : class_info.base_classes) {
                            const std::string& base_class_with_context = base_class.get_full_class_name();
                            if (base_class.is_virtual_inherited) {
                                generated_file << separator << "cereal::virtual_base_class<" << base_class_with_context << ">(&m)";
                            } else {
                                generated_file << separator << "cereal::base_class<" << base_class_with_context << ">(&m)";
                            }
                            separator = ",\n            ";
                        }
                        generated_file << ");\n";
                    }
                    generated_file << "    serializer_class<" << context_of_declaration << ">::do_" << function_type
                                   << "(archive, m);\n";
                    generated_file << "}\n";
                    for (auto& archive_type : archive_types[function_type]) {
                        generated_file << "template void " << function_type << "<" << archive_type << ">(" << archive_type << "&, "
                                       << param_const[function_type] << context_of_declaration << "&);\n";
                    }
                    generated_file << "\n";
                }
                if (class_info.is_polymorphic) {
                    polymorphic_classes.push_back(context_of_declaration);
                    if (!class_info.is_abstract) {
                        polymorphic_classes_to_force_serialize.push_back(context_of_declaration);
                    }
                }
                for (auto& poly_class_info : class_info.additonal_required_polymorphic_register) {
                    polymorphic_classes.push_back(poly_class_info.get_full_class_name());
                    if (!poly_class_info.is_abstract) {
                        polymorphic_classes_to_force_serialize.push_back(poly_class_info.get_full_class_name());
                    }
                }

                for (auto& poly_relation_info : class_info.additonal_required_polymorphic_relation) {
                    polymorphic_relations.emplace_back(poly_relation_info.first.get_full_class_name(),
                                                       poly_relation_info.second.get_full_class_name());
                }

                generated_file << "\n\n";
            }
        }

        if (polymorphic_classes_to_force_serialize.size() > 0) {
            std::string function_name = "force_serialization";
            generated_file << "template<class Archive>\n";
            generated_file << "static void\n";
            generated_file << function_name << "(Archive& ar)\n";
            generated_file << "{\n";
            size_t var_index = 0;
            for (auto& class_to_add : polymorphic_classes_to_force_serialize) {
                generated_file << "    " << class_to_add.str() << " var" << var_index << ";\n";
                generated_file << "    ar(var" << var_index << ");\n";
                var_index++;
            }
            generated_file << "}\n";

            for (auto& archive_types_per_direction : archive_types) {
                for (auto& archive_type : archive_types_per_direction.second) {
                    generated_file << "template void " << function_name << "<" << archive_type << ">(" << archive_type << "&);\n";
                }
            }
        }

        generated_file << "}\n\n";
        if (polymorphic_classes.size() > 0) {
            generated_file << "#pragma GCC diagnostic push\n";
            generated_file << "#pragma GCC diagnostic ignored \"-Wunused-parameter\"\n\n";
            // registering polymorphic types. this shoud be done in global namespace
            // each class should be registered once, keeping set of added classes
            std::set<StringRef> added_polymorphic_classes;
            for (auto& polymorphic_class : polymorphic_classes) {
                if (added_polymorphic_classes.count(polymorphic_class) == 0) {
                    generated_file << "CEREAL_REGISTER_TYPE(" << polymorphic_class.str() << ");\n";
                }
                added_polymorphic_classes.insert(polymorphic_class);
            }
            // each classes pair should be added once, keeping set of added classes pairs
            std::set<std::pair<std::string, std::string>> added_polymorphic_relations;
            for (auto& polymorphic_relation : polymorphic_relations) {
                replace_all(polymorphic_relation.first, ",", " CEREAL_GEN_COMMA() ");
                replace_all(polymorphic_relation.second, ",", " CEREAL_GEN_COMMA() ");
                if (added_polymorphic_relations.count(polymorphic_relation) == 0) {
                    generated_file << "CEREAL_REGISTER_POLYMORPHIC_RELATION(" << polymorphic_relation.first << ", "
                                   << polymorphic_relation.second << ");\n";
                }
                added_polymorphic_relations.insert(polymorphic_relation);
            }
            generated_file << "\n";
            generated_file << "#pragma GCC diagnostic pop\n\n";
        }
    }
}

int
main(int argc, const char** argv)
{
    initialize_all_include_paths(argc, argv);
    CommonOptionsParser op(argc, argv, ToolingSampleCategory);
    ClangTool Tool(op.getCompilations(), op.getSourcePathList());
    initialize_data_from_config_file();

    int result = Tool.run(newFrontendActionFactory<MyFrontendAction>().get());
    if (result == 1) {
        exit(1);
    }
    create_cpp_file_for_cereal();
    exit(0);
}
