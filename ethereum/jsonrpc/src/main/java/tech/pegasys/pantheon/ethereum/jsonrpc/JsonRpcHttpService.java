/*
 * Copyright 2018 ConsenSys AG.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with
 * the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on
 * an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 */
package tech.pegasys.pantheon.ethereum.jsonrpc;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.collect.Streams.stream;
import static java.util.stream.Collectors.toList;
import static tech.pegasys.pantheon.util.NetworkUtility.urlForSocketAddress;

import tech.pegasys.pantheon.ethereum.jsonrpc.internal.JsonRpcRequest;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.JsonRpcRequestId;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.exception.InvalidJsonRpcParameters;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.methods.JsonRpcMethod;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcError;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcErrorResponse;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcNoResponse;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcResponse;
import tech.pegasys.pantheon.ethereum.jsonrpc.internal.response.JsonRpcResponseType;
import tech.pegasys.pantheon.metrics.LabelledMetric;
import tech.pegasys.pantheon.metrics.MetricCategory;
import tech.pegasys.pantheon.metrics.MetricsSystem;
import tech.pegasys.pantheon.metrics.OperationTimer;
import tech.pegasys.pantheon.metrics.OperationTimer.TimingContext;
import tech.pegasys.pantheon.util.NetworkUtility;

import java.net.InetSocketAddress;
import java.net.SocketException;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.StringJoiner;
import java.util.concurrent.CompletableFuture;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Splitter;
import com.google.common.collect.Iterables;
import io.netty.handler.codec.http.HttpResponseStatus;
import io.vertx.core.CompositeFuture;
import io.vertx.core.Future;
import io.vertx.core.Handler;
import io.vertx.core.Vertx;
import io.vertx.core.http.HttpMethod;
import io.vertx.core.http.HttpServer;
import io.vertx.core.http.HttpServerOptions;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.json.DecodeException;
import io.vertx.core.json.Json;
import io.vertx.core.json.JsonArray;
import io.vertx.core.json.JsonObject;
import io.vertx.ext.auth.AuthProvider;
import io.vertx.ext.auth.User;
import io.vertx.ext.auth.jwt.JWTAuth;
import io.vertx.ext.auth.jwt.JWTAuthOptions;
import io.vertx.ext.jwt.JWTOptions;
import io.vertx.ext.web.Router;
import io.vertx.ext.web.RoutingContext;
import io.vertx.ext.web.handler.BodyHandler;
import io.vertx.ext.web.handler.CorsHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class JsonRpcHttpService {

  private static final Logger LOG = LogManager.getLogger();

  private static final InetSocketAddress EMPTY_SOCKET_ADDRESS = new InetSocketAddress("0.0.0.0", 0);
  private static final String APPLICATION_JSON = "application/json";
  private static final JsonRpcResponse NO_RESPONSE = new JsonRpcNoResponse();
  private static final String EMPTY_RESPONSE = "";

  private final Vertx vertx;
  private final JsonRpcConfiguration config;
  private final Map<String, JsonRpcMethod> jsonRpcMethods;
  private final Path dataDir;
  private final LabelledMetric<OperationTimer> requestTimer;

  private final Optional<JWTAuth> jwtAuthProvider;
  private final Optional<AuthProvider> credentialAuthProvider;

  private HttpServer httpServer;

  /**
   * Construct a JsonRpcHttpService handler that has authentication enabled
   *
   * @param vertx The vertx process that will be running this service
   * @param dataDir The data directory where requests can be buffered
   * @param config Configuration for the rpc methods being loaded
   * @param metricsSystem The metrics service that activities should be reported to
   * @param methods The json rpc methods that should be enabled
   * @param jwtOptions The configuration for the jwt auth provider
   * @param credentialAuthProvider An auth provider that is backed by a credentials store
   */
  public JsonRpcHttpService(
      final Vertx vertx,
      final Path dataDir,
      final JsonRpcConfiguration config,
      final MetricsSystem metricsSystem,
      final Map<String, JsonRpcMethod> methods,
      final JWTAuthOptions jwtOptions,
      final AuthProvider credentialAuthProvider) {
    this(
        vertx,
        dataDir,
        config,
        metricsSystem,
        methods,
        Optional.of(jwtOptions),
        Optional.of(credentialAuthProvider));
  }

  /**
   * Construct a JsonRpcHttpService handler that doesn't have authentication enabled
   *
   * @param vertx The vertx process that will be running this service
   * @param dataDir The data directory where requests can be buffered
   * @param config Configuration for the rpc methods being loaded
   * @param metricsSystem The metrics service that activities should be reported to
   * @param methods The json rpc methods that should be enabled
   */
  public JsonRpcHttpService(
      final Vertx vertx,
      final Path dataDir,
      final JsonRpcConfiguration config,
      final MetricsSystem metricsSystem,
      final Map<String, JsonRpcMethod> methods) {
    this(vertx, dataDir, config, metricsSystem, methods, Optional.empty(), Optional.empty());
  }

  private JsonRpcHttpService(
      final Vertx vertx,
      final Path dataDir,
      final JsonRpcConfiguration config,
      final MetricsSystem metricsSystem,
      final Map<String, JsonRpcMethod> methods,
      final Optional<JWTAuthOptions> jwtOptions,
      final Optional<AuthProvider> credentialAuthProvider) {
    this.dataDir = dataDir;
    requestTimer =
        metricsSystem.createLabelledTimer(
            MetricCategory.RPC,
            "request_time",
            "Time taken to process a JSON-RPC request",
            "methodName");
    validateConfig(config);
    this.config = config;
    this.vertx = vertx;
    this.jsonRpcMethods = methods;
    this.credentialAuthProvider = credentialAuthProvider;
    jwtAuthProvider = jwtOptions.map(options -> JWTAuth.create(vertx, options));
  }

  private void validateConfig(final JsonRpcConfiguration config) {
    checkArgument(
        config.getPort() == 0 || NetworkUtility.isValidPort(config.getPort()),
        "Invalid port configuration.");
    checkArgument(config.getHost() != null, "Required host is not configured.");
  }

  public CompletableFuture<?> start() {
    LOG.info("Starting JsonRPC service on {}:{}", config.getHost(), config.getPort());
    // Create the HTTP server and a router object.
    httpServer =
        vertx.createHttpServer(
            new HttpServerOptions().setHost(config.getHost()).setPort(config.getPort()));

    // Handle json rpc requests
    final Router router = Router.router(vertx);

    // Verify Host header to avoid rebind attack.
    router.route().handler(checkWhitelistHostHeader());

    router
        .route()
        .handler(
            CorsHandler.create(buildCorsRegexFromConfig())
                .allowedHeader("*")
                .allowedHeader("content-type"));
    router
        .route()
        .handler(
            BodyHandler.create()
                .setUploadsDirectory(dataDir.resolve("uploads").toString())
                .setDeleteUploadedFilesOnEnd(true));
    router.route("/").method(HttpMethod.GET).handler(this::handleEmptyRequest);
    router
        .route("/")
        .method(HttpMethod.POST)
        .produces(APPLICATION_JSON)
        .handler(this::handleJsonRPCRequest);
    router
        .route("/login")
        .method(HttpMethod.POST)
        .produces(APPLICATION_JSON)
        .handler(this::handleLogin);

    final CompletableFuture<?> resultFuture = new CompletableFuture<>();
    httpServer
        .requestHandler(router)
        .listen(
            res -> {
              if (!res.failed()) {
                resultFuture.complete(null);
                LOG.info(
                    "JsonRPC service started and listening on {}:{}",
                    config.getHost(),
                    httpServer.actualPort());
                return;
              }
              httpServer = null;
              final Throwable cause = res.cause();
              if (cause instanceof SocketException) {
                resultFuture.completeExceptionally(
                    new JsonRpcServiceException(
                        String.format(
                            "Failed to bind Ethereum JSON RPC listener to %s:%s: %s",
                            config.getHost(), config.getPort(), cause.getMessage())));
                return;
              }
              resultFuture.completeExceptionally(cause);
            });

    return resultFuture;
  }

  private Handler<RoutingContext> checkWhitelistHostHeader() {
    return event -> {
      final Optional<String> hostHeader = getAndValidateHostHeader(event);
      if (config.getHostsWhitelist().contains("*")
          || (hostHeader.isPresent() && hostIsInWhitelist(hostHeader.get()))) {
        event.next();
      } else {
        event
            .response()
            .setStatusCode(403)
            .putHeader("Content-Type", "application/json; charset=utf-8")
            .end("{\"message\":\"Host not authorized.\"}");
      }
    };
  }

  private Optional<String> getAndValidateHostHeader(final RoutingContext event) {
    final Iterable<String> splitHostHeader = Splitter.on(':').split(event.request().host());
    final long hostPieces = stream(splitHostHeader).count();
    if (hostPieces > 1) {
      // If the host contains a colon, verify the host is correctly formed - host [ ":" port ]
      if (hostPieces > 2 || !Iterables.get(splitHostHeader, 1).matches("\\d{1,5}+")) {
        return Optional.empty();
      }
    }
    return Optional.ofNullable(Iterables.get(splitHostHeader, 0));
  }

  private boolean hostIsInWhitelist(final String hostHeader) {
    return config
        .getHostsWhitelist()
        .stream()
        .anyMatch(whitelistEntry -> whitelistEntry.toLowerCase().equals(hostHeader.toLowerCase()));
  }

  public CompletableFuture<?> stop() {
    if (httpServer == null) {
      return CompletableFuture.completedFuture(null);
    }

    final CompletableFuture<?> resultFuture = new CompletableFuture<>();
    httpServer.close(
        res -> {
          if (res.failed()) {
            resultFuture.completeExceptionally(res.cause());
          } else {
            httpServer = null;
            resultFuture.complete(null);
          }
        });
    return resultFuture;
  }

  public InetSocketAddress socketAddress() {
    if (httpServer == null) {
      return EMPTY_SOCKET_ADDRESS;
    }
    return new InetSocketAddress(config.getHost(), httpServer.actualPort());
  }

  @VisibleForTesting
  public String url() {
    if (httpServer == null) {
      return "";
    }
    return urlForSocketAddress("http", socketAddress());
  }

  private void handleJsonRPCRequest(final RoutingContext routingContext) {
    // Parse json
    try {
      final String json = routingContext.getBodyAsString().trim();
      if (!json.isEmpty() && json.charAt(0) == '{') {
        handleJsonSingleRequest(routingContext, new JsonObject(json));
      } else {
        final JsonArray array = new JsonArray(json);
        if (array.size() < 1) {
          handleJsonRpcError(routingContext, null, JsonRpcError.INVALID_REQUEST);
          return;
        }
        handleJsonBatchRequest(routingContext, array);
      }
    } catch (final DecodeException ex) {
      handleJsonRpcError(routingContext, null, JsonRpcError.PARSE_ERROR);
    }
  }

  // Facilitate remote health-checks in AWS, inter alia.
  private void handleEmptyRequest(final RoutingContext routingContext) {
    routingContext.response().setStatusCode(201).end();
  }

  private void handleJsonSingleRequest(
      final RoutingContext routingContext, final JsonObject request) {
    final HttpServerResponse response = routingContext.response();
    vertx.executeBlocking(
        future -> {
          final JsonRpcResponse jsonRpcResponse = process(request);
          future.complete(jsonRpcResponse);
        },
        false,
        (res) -> {
          if (res.failed()) {
            response.setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code()).end();
            return;
          }

          final JsonRpcResponse jsonRpcResponse = (JsonRpcResponse) res.result();
          response.setStatusCode(status(jsonRpcResponse).code());
          response.putHeader("Content-Type", APPLICATION_JSON);
          response.end(serialise(jsonRpcResponse));
        });
  }

  private void handleLogin(final RoutingContext routingContext) {
    if (!jwtAuthProvider.isPresent() || !credentialAuthProvider.isPresent()) {
      routingContext
          .response()
          .setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
          .setStatusMessage("Authentication not enabled")
          .end();
      return;
    }

    final JsonObject requestBody = routingContext.getBodyAsJson();

    if (requestBody == null) {
      routingContext
          .response()
          .setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
          .setStatusMessage(HttpResponseStatus.BAD_REQUEST.reasonPhrase())
          .end();
      return;
    }

    // Check user
    final JsonObject authParams = new JsonObject();
    authParams.put("username", requestBody.getValue("username"));
    authParams.put("password", requestBody.getValue("password"));
    credentialAuthProvider
        .get()
        .authenticate(
            authParams,
            (r) -> {
              if (r.failed()) {
                routingContext
                    .response()
                    .setStatusCode(HttpResponseStatus.UNAUTHORIZED.code())
                    .setStatusMessage(HttpResponseStatus.UNAUTHORIZED.reasonPhrase())
                    .end();
              } else {
                final User user = r.result();

                final JWTOptions options = new JWTOptions().setExpiresInMinutes(5);
                final String token = jwtAuthProvider.get().generateToken(user.principal(), options);

                final JsonObject responseBody = new JsonObject().put("token", token);
                final HttpServerResponse response = routingContext.response();
                response.setStatusCode(200);
                response.putHeader("Content-Type", APPLICATION_JSON);
                response.end(responseBody.encode());
              }
            });
  }

  private HttpResponseStatus status(final JsonRpcResponse response) {

    switch (response.getType()) {
      case ERROR:
        return HttpResponseStatus.BAD_REQUEST;
      case SUCCESS:
      case NONE:
      default:
        return HttpResponseStatus.OK;
    }
  }

  private String serialise(final JsonRpcResponse response) {

    if (response.getType() == JsonRpcResponseType.NONE) {
      return EMPTY_RESPONSE;
    }

    return Json.encodePrettily(response);
  }

  @SuppressWarnings("rawtypes")
  private void handleJsonBatchRequest(
      final RoutingContext routingContext, final JsonArray jsonArray) {
    // Interpret json as rpc request
    final List<Future> responses =
        jsonArray
            .stream()
            .map(
                obj -> {
                  if (!(obj instanceof JsonObject)) {
                    return Future.succeededFuture(
                        errorResponse(null, JsonRpcError.INVALID_REQUEST));
                  }

                  final JsonObject req = (JsonObject) obj;
                  final Future<JsonRpcResponse> fut = Future.future();
                  vertx.executeBlocking(
                      future -> future.complete(process(req)),
                      false,
                      ar -> {
                        if (ar.failed()) {
                          fut.fail(ar.cause());
                        } else {
                          fut.complete((JsonRpcResponse) ar.result());
                        }
                      });
                  return fut;
                })
            .collect(toList());

    CompositeFuture.all(responses)
        .setHandler(
            (res) -> {
              if (res.failed()) {
                routingContext
                    .response()
                    .setStatusCode(HttpResponseStatus.INTERNAL_SERVER_ERROR.code())
                    .end();
                return;
              }
              final JsonRpcResponse[] completed =
                  res.result()
                      .list()
                      .stream()
                      .map(JsonRpcResponse.class::cast)
                      .filter(this::isNonEmptyResponses)
                      .toArray(JsonRpcResponse[]::new);

              routingContext.response().end(Json.encode(completed));
            });
  }

  private boolean isNonEmptyResponses(final JsonRpcResponse result) {
    return result.getType() != JsonRpcResponseType.NONE;
  }

  private JsonRpcResponse process(final JsonObject requestJson) {
    final JsonRpcRequest request;
    Object id = null;
    try {
      id = new JsonRpcRequestId(requestJson.getValue("id")).getValue();
      request = requestJson.mapTo(JsonRpcRequest.class);
    } catch (final IllegalArgumentException exception) {
      return errorResponse(id, JsonRpcError.INVALID_REQUEST);
    }
    // Handle notifications
    if (request.isNotification()) {
      // Notifications aren't handled so create empty result for now.
      return NO_RESPONSE;
    }

    LOG.debug("JSON-RPC request -> {}", request.getMethod());
    // Find method handler
    final JsonRpcMethod method = jsonRpcMethods.get(request.getMethod());
    if (method == null) {
      return errorResponse(id, JsonRpcError.METHOD_NOT_FOUND);
    }

    // Generate response
    try (final TimingContext ignored = requestTimer.labels(request.getMethod()).startTimer()) {
      return method.response(request);
    } catch (final InvalidJsonRpcParameters e) {
      LOG.debug(e);
      return errorResponse(id, JsonRpcError.INVALID_PARAMS);
    }
  }

  private void handleJsonRpcError(
      final RoutingContext routingContext, final Object id, final JsonRpcError error) {
    routingContext
        .response()
        .setStatusCode(HttpResponseStatus.BAD_REQUEST.code())
        .end(Json.encode(new JsonRpcErrorResponse(id, error)));
  }

  private JsonRpcResponse errorResponse(final Object id, final JsonRpcError error) {
    return new JsonRpcErrorResponse(id, error);
  }

  private String buildCorsRegexFromConfig() {
    if (config.getCorsAllowedDomains().isEmpty()) {
      return "";
    }
    if (config.getCorsAllowedDomains().contains("*")) {
      return "*";
    } else {
      final StringJoiner stringJoiner = new StringJoiner("|");
      config.getCorsAllowedDomains().stream().filter(s -> !s.isEmpty()).forEach(stringJoiner::add);
      return stringJoiner.toString();
    }
  }
}
