// NOLINT(namespace-envoy)
#include <string>
#include <string_view>
#include <unordered_map>

#include "modsecurity/modsecurity.h"
#include "modsecurity/rules_set.h"
#include "proxy_wasm_intrinsics.h"

#include "utils.h"

class ExampleRootContext : public RootContext {
public:
  explicit ExampleRootContext(uint32_t id, std::string_view root_id) : RootContext(id, root_id) {}

  bool onStart(size_t /* vm_configuration_size */) override;
  bool onConfigure(size_t /* configuration_size */) override;
  void onTick() override;

  std::string configuration() { return configuration_; };

private:
  std::string configuration_;
};

class ExampleContext : public Context {
public:
  explicit ExampleContext(uint32_t id, RootContext* root) : Context(id, root) {}

  void onCreate() override;

  FilterHeadersStatus onRequestHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onRequestBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterMetadataStatus onRequestMetadata(uint32_t) override;
  FilterTrailersStatus onRequestTrailers(uint32_t) override;

  FilterHeadersStatus onResponseHeaders(uint32_t headers, bool end_of_stream) override;
  FilterDataStatus onResponseBody(size_t body_buffer_length, bool end_of_stream) override;
  FilterMetadataStatus onResponseMetadata(uint32_t) override;
  FilterTrailersStatus onResponseTrailers(uint32_t) override;

  void onDone() override;
  void onLog() override;
  void onDelete() override;

  // get config
  const std::string& rules_inline() const { return rules_inline_; }

  std::shared_ptr<modsecurity::ModSecurity> modsec() const { return modsec_; }
  std::shared_ptr<modsecurity::RulesSet> modsec_rules() const { return modsec_rules_; }

private:
  // rules config data from root context configurations
  std::string rules_inline_;

  // share modsecurity obj
  std::shared_ptr<modsecurity::ModSecurity> modsec_;
  std::shared_ptr<modsecurity::RulesSet> modsec_rules_;
  std::shared_ptr<modsecurity::Transaction> modsec_transaction_;

  FilterHeadersStatus getRequestHeadersStatus();

  /**
   * @return true if intervention of current transaction is disruptive, false otherwise
   */
  bool intervention();

  struct ModSecurityStatus {
    ModSecurityStatus() : intervined(0), request_processed(0), response_processed(0) {}
    bool intervined;
    bool request_processed;
    bool response_processed;
  };

  ModSecurityStatus status_;
};

static RegisterContextFactory register_ExampleContext(CONTEXT_FACTORY(ExampleContext),
                                                      ROOT_FACTORY(ExampleRootContext),
                                                      "my_root_id");

void ExampleRootContext::onTick() { LOG_TRACE("onTick"); }

bool ExampleRootContext::onStart(size_t vm_configuration_size) {
  LOG_TRACE("onStart");
  auto vm_configuration_data = getBufferBytes(WasmBufferType::VmConfiguration, 0, vm_configuration_size);
  std::string vm_configuration = vm_configuration_data->toString();
  LOG_INFO(std::string("vm configurations: ") + vm_configuration);
  return true;
}

bool ExampleRootContext::onConfigure(size_t configuration_size) {
  LOG_WARN("onConfigure");
  proxy_set_tick_period_milliseconds(1000); // 1 sec
  auto configuration_data = getBufferBytes(WasmBufferType::PluginConfiguration, 0, configuration_size);
  configuration_ = configuration_data->toString();
  return true;
}

void ExampleContext::onCreate() {
  LOG_WARN(std::string("onCreate " + std::to_string(id())));

  // modsecurity initializing
  ExampleRootContext* root = dynamic_cast<ExampleRootContext*>(this->root());
  rules_inline_ = root->configuration();
  LOG_INFO(std::string("onCreate load configurations: ") + rules_inline_);
  modsec_.reset(new modsecurity::ModSecurity());
  modsec_->setConnectorInformation("ModSecurity-envoy v3.0.4 (ModSecurity)");
  modsec_rules_.reset(new modsecurity::RulesSet());
  if (!rules_inline().empty()) {
      int rulesLoaded = modsec_rules_->load(rules_inline().c_str());
      LOG_DEBUG("Loading ModSecurity inline rules");
      if (rulesLoaded == -1) {
          LOG_ERROR(std::string("Failed to load rules"));
      } else {
          LOG_INFO(std::string("Loaded inline rules: ") + std::to_string(rulesLoaded));
      };
  }
  modsec_transaction_.reset(new modsecurity::Transaction(modsec().get(), modsec_rules().get(), this));
}

FilterHeadersStatus ExampleContext::onRequestHeaders(uint32_t /* headers */, bool end_of_stream) {
  LOG_DEBUG(std::string("onRequestHeaders ") + std::to_string(id()));
  if (status_.intervined || status_.request_processed) {
    LOG_DEBUG("Processed");
    return getRequestHeadersStatus();
  }

  // modsecurity processConnection
  std::string remote_addr;
  int remote_port;
  std::string local_addr;
  int local_port;
  getValue({"source", "address"}, &remote_addr);
  getValue({"source", "port"}, &remote_port);
  getValue({"destination", "address"}, &local_addr);
  getValue({"destination", "port"}, &local_port);
  LOG_INFO(std::string("source address: ") + remote_addr + std::string(", dest address: ") + local_addr);
  modsec_transaction_->processConnection(split(remote_addr, ":")[0].c_str(), remote_port,
                                         split(local_addr, ":")[0].c_str(), local_port);
  if (intervention()) {
    return FilterHeadersStatus::StopIteration;
  }

  // modsecurity processURI
  std::string path = getRequestHeader(":path")->toString();
  std::string method = getRequestHeader(":method")->toString();
  std::string protocol;
  getValue({"request", "protocol"}, &protocol);
  modsec_transaction_->processURI(path.c_str(), method.c_str(), protocol.c_str());
  if (intervention()) {
    return FilterHeadersStatus::StopIteration;
  }

  // modsecurity processRequestHeaders
  auto result = getRequestHeaderPairs();
  auto pairs = result->pairs();
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
    modsec_transaction_->addRequestHeader(std::string(p.first), std::string(p.second));
  }
  modsec_transaction_->processRequestHeaders();
  if (end_of_stream) {
    status_.request_processed = true;
  }
  if (intervention()) {
    return FilterHeadersStatus::StopIteration;
  }

  return getRequestHeadersStatus();
}

FilterHeadersStatus ExampleContext::onResponseHeaders(uint32_t /* headers */, bool /* end_of_stream */) {
  LOG_DEBUG(std::string("onResponseHeaders ") + std::to_string(id()));
  auto result = getResponseHeaderPairs();
  auto pairs = result->pairs();
  LOG_INFO(std::string("headers: ") + std::to_string(pairs.size()));
  for (auto& p : pairs) {
    LOG_INFO(std::string(p.first) + std::string(" -> ") + std::string(p.second));
  }

  addResponseHeader("X-Wasm-custom", "FOO");
  replaceResponseHeader("content-type", "text/plain; charset=utf-8");
  removeResponseHeader("content-length");
  return FilterHeadersStatus::Continue;
}

FilterDataStatus ExampleContext::onRequestBody(size_t body_buffer_length,
                                               bool /* end_of_stream */) {
  auto body = getBufferBytes(WasmBufferType::HttpRequestBody, 0, body_buffer_length);
  LOG_ERROR(std::string("onRequestBody ") + std::string(body->view()));
  return FilterDataStatus::Continue;
}

FilterDataStatus ExampleContext::onResponseBody(size_t /* body_buffer_length */,
                                                bool /* end_of_stream */) {
  setBuffer(WasmBufferType::HttpResponseBody, 0, 12, "Hello, world");
  return FilterDataStatus::Continue;
}

FilterMetadataStatus ExampleContext::onRequestMetadata(uint32_t) {
  return FilterMetadataStatus::Continue;
}

FilterMetadataStatus ExampleContext::onResponseMetadata(uint32_t) {
  return FilterMetadataStatus::Continue;
}

FilterTrailersStatus ExampleContext::onRequestTrailers(uint32_t) {
  return FilterTrailersStatus::Continue;
}

FilterTrailersStatus ExampleContext::onResponseTrailers(uint32_t) {
  return FilterTrailersStatus::Continue;
}

void ExampleContext::onDone() { LOG_WARN(std::string("onDone " + std::to_string(id()))); }

void ExampleContext::onLog() { LOG_WARN(std::string("onLog " + std::to_string(id()))); }

void ExampleContext::onDelete() { LOG_WARN(std::string("onDelete " + std::to_string(id()))); }

bool ExampleContext::intervention() {
    if (!status_.intervined && modsec_transaction_->m_it.disruptive) {
        // status_.intervined must be set to true before sendLocalReply to avoid reentrancy when encoding the reply
        status_.intervined = true;
        LOG_DEBUG("intervention");
    }
    return status_.intervined;
}

FilterHeadersStatus ExampleContext::getRequestHeadersStatus() {
    if (status_.intervined) {
        LOG_DEBUG("StopIteration");
        return FilterHeadersStatus::StopIteration;
    }
    if (status_.request_processed) {
        LOG_DEBUG("Continue");
        return FilterHeadersStatus::Continue;
    }
    // If disruptive, hold until status_.request_processed, otherwise let the data flow.
    LOG_DEBUG("RuleEngine");
    return modsec_transaction_->getRuleEngineState() == modsecurity::RulesSetProperties::EnabledRuleEngine ?
                FilterHeadersStatus::StopIteration : FilterHeadersStatus::Continue;
}

