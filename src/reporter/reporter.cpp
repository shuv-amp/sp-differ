// SPDX-License-Identifier: MIT
#include "reporter.h"

#include <fstream>
#include <sstream>

namespace sp_differ {
namespace {

std::string EscapeJson(const std::string& value) {
  std::ostringstream out;
  for (unsigned char ch : value) {
    switch (ch) {
      case '"':
        out << "\\\"";
        break;
      case '\\':
        out << "\\\\";
        break;
      case '\b':
        out << "\\b";
        break;
      case '\f':
        out << "\\f";
        break;
      case '\n':
        out << "\\n";
        break;
      case '\r':
        out << "\\r";
        break;
      case '\t':
        out << "\\t";
        break;
      default:
        if (ch < 0x20) {
          static const char* kHex = "0123456789abcdef";
          out << "\\u00" << kHex[(ch >> 4) & 0x0F] << kHex[ch & 0x0F];
        } else {
          out << static_cast<char>(ch);
        }
        break;
    }
  }
  return out.str();
}

bool WriteTextFile(const std::string& path, const std::string& text, std::string* error) {
  std::ofstream file(path, std::ios::binary);
  if (!file) {
    if (error != nullptr) {
      *error = "unable to write report: " + path;
    }
    return false;
  }
  file << text;
  if (!file.good()) {
    if (error != nullptr) {
      *error = "unable to flush report: " + path;
    }
    return false;
  }
  return true;
}

}  // namespace

bool WriteSuiteReportJson(const SuiteReport& report, const std::string& path,
                          std::string* error) {
  std::ostringstream out;
  out << "{\n"
      << "  \"suite_name\": \"" << EscapeJson(report.suite_name) << "\",\n"
      << "  \"worker\": \"" << EscapeJson(report.worker) << "\",\n"
      << "  \"semantic_worker\": \"" << EscapeJson(report.semantic_worker) << "\",\n"
      << "  \"total_count\": " << report.total_count << ",\n"
      << "  \"passed_count\": " << report.passed_count << ",\n"
      << "  \"failed_count\": " << report.failed_count << ",\n"
      << "  \"cases\": [\n";
  for (size_t i = 0; i < report.cases.size(); ++i) {
    const CaseReport& item = report.cases[i];
    out << "    {\n"
        << "      \"case_path\": \"" << EscapeJson(item.case_path) << "\",\n"
        << "      \"case_format_version\": " << item.case_format_version << ",\n"
        << "      \"execution_mode\": \"" << EscapeJson(item.execution_mode) << "\",\n"
        << "      \"implementation\": \"" << EscapeJson(item.implementation) << "\",\n"
        << "      \"expected_path\": \"" << EscapeJson(item.expected_path) << "\",\n"
        << "      \"source_id\": \"" << EscapeJson(item.source_id) << "\",\n"
        << "      \"semantic_status\": \"" << EscapeJson(item.semantic_status) << "\",\n"
        << "      \"passed\": " << (item.passed ? "true" : "false") << ",\n"
        << "      \"detail\": \"" << EscapeJson(item.detail) << "\"\n"
        << "    }";
    if (i + 1 != report.cases.size()) {
      out << ",";
    }
    out << "\n";
  }
  out << "  ]\n"
      << "}\n";
  return WriteTextFile(path, out.str(), error);
}

bool WriteSuiteReportMarkdown(const SuiteReport& report, const std::string& path,
                              std::string* error) {
  std::ostringstream out;
  out << "# SP-DIFFER Suite Report\n\n"
      << "- suite: `" << report.suite_name << "`\n"
      << "- v1 worker: `" << report.worker << "`\n"
      << "- semantic worker: `" << report.semantic_worker << "`\n"
      << "- cases: `" << report.total_count << "`\n"
      << "- passed: `" << report.passed_count << "`\n"
      << "- failed: `" << report.failed_count << "`\n\n";

  if (report.cases.empty()) {
    out << "No cases were executed.\n";
    return WriteTextFile(path, out.str(), error);
  }

  out << "## Cases\n\n";
  for (const CaseReport& item : report.cases) {
    out << "### `" << item.source_id << "`\n\n"
        << "- case: `" << item.case_path << "`\n"
        << "- format: `" << item.case_format_version << "`\n"
        << "- mode: `" << item.execution_mode << "`\n"
        << "- implementation: `" << item.implementation << "`\n"
        << "- semantic_status: `" << item.semantic_status << "`\n"
        << "- result: `" << (item.passed ? "passed" : "failed") << "`\n";
    if (!item.expected_path.empty()) {
      out << "- expected: `" << item.expected_path << "`\n";
    }
    if (!item.detail.empty()) {
      out << "- detail: `" << item.detail << "`\n";
    }
    out << "\n";
  }

  return WriteTextFile(path, out.str(), error);
}

}  // namespace sp_differ
