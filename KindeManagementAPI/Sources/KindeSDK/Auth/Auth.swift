import Foundation
import AppAuth
import os.log
#if canImport(UIKit)
import UIKit
#endif

/// The Kinde authentication service
@available(iOS 16.0, *)
public final class Auth {
    @Atomic private var currentAuthorizationFlow: OIDExternalUserAgentSession?
    
    private let config: Config
    private let authStateRepository: AuthStateRepository
    private let logger: LoggerProtocol
    private var privateAuthSession: Bool = false
    
    init(config: Config, authStateRepository: AuthStateRepository, logger: LoggerProtocol) {
        self.config = config
        self.authStateRepository = authStateRepository
        self.logger = logger
    }
    
    // MARK: - Service Properties
    
    /// Claims service for accessing user claims from tokens
    public lazy var claims: ClaimsService = ClaimsService(auth: self, logger: logger)
    
    /// Mobile entitlements system for client-side validation
    public lazy var entitlements: MobileEntitlements = MobileEntitlements(auth: self, logger: logger)
    
    /// Is the user authenticated as of the last use of authentication state?
    public func isAuthorized() -> Bool {
        return authStateRepository.state?.isAuthorized ?? false
    }
    
    public func isAuthenticated() -> Bool {
        let isAuthorized = authStateRepository.state?.isAuthorized
        guard let lastTokenResponse = authStateRepository.state?.lastTokenResponse else {
            return false
        }
        guard let accessTokenExpirationDate = lastTokenResponse.accessTokenExpirationDate else {
            return false
        }
        return lastTokenResponse.accessToken != nil &&
               isAuthorized == true &&
               accessTokenExpirationDate > Date()
    }
    
    public func getUserDetails() -> User? {
        guard let params = authStateRepository.state?.lastTokenResponse?.idToken?.parsedJWT else {
            return nil
        }
        if let idValue = params["sub"] as? String,
           let email = params["email"] as? String {
            let givenName = params["given_name"] as? String
            let familyName = params["family_name"] as? String
            let picture = params["picture"] as? String
            return User(id: idValue,
                        email: email,
                        lastName: familyName,
                        firstName: givenName,
                        picture: picture)
        }
        return nil
    }
    

    public func getClaim(forKey key: String, token: TokenType = .accessToken) -> Claim? {
        let lastTokenResponse = authStateRepository.state?.lastTokenResponse
        let tokenToParse = token == .accessToken ? lastTokenResponse?.accessToken: lastTokenResponse?.idToken
        guard let params = tokenToParse?.parsedJWT else {
            return nil
        }
        if let valueOrNil = params[key],
            let value = valueOrNil {
            return Claim(name: key, value: value)
        }
        return nil
    }
    
    @available(*, deprecated, message: "Use getClaim(forKey:token:) with return type Claim?")
    public func getClaim(key: String, token: TokenType = .accessToken) -> Any? {
        let lastTokenResponse = authStateRepository.state?.lastTokenResponse
        let tokenToParse = token == .accessToken ? lastTokenResponse?.accessToken: lastTokenResponse?.idToken
        guard let params = tokenToParse?.parsedJWT else {
            return nil
        }
        if !params.keys.contains(key) {
            os_log("The claimed value of \"%@\" does not exist in your token", log: .default, type: .error, key)
        }
        return params[key] ?? nil
    }
    
    public func getPermissions() -> Permissions? {
        if let permissionsClaim = getClaim(forKey: ClaimKey.permissions.rawValue),
           let permissionsArray = permissionsClaim.value as? [String],
           let orgCodeClaim = getClaim(forKey: ClaimKey.organisationCode.rawValue),
           let orgCode = orgCodeClaim.value as? String {
            
            let organization = Organization(code: orgCode)
            let permissions = Permissions(organization: organization,
                                          permissions: permissionsArray)
            return permissions
        }
        return nil
    }
    
    public func getPermission(name: String) -> Permission? {
        if let permissionsClaim = getClaim(forKey: ClaimKey.permissions.rawValue),
           let permissionsArray = permissionsClaim.value as? [String],
           let orgCodeClaim = getClaim(forKey: ClaimKey.organisationCode.rawValue),
           let orgCode = orgCodeClaim.value as? String {
            
            let organization = Organization(code: orgCode)
            let permission = Permission(organization: organization,
                                        isGranted: permissionsArray.contains(name))
            return permission
        }
        return nil
    }
    
    public func getOrganization() -> Organization? {
        if let orgCodeClaim = getClaim(forKey: ClaimKey.organisationCode.rawValue),
           let orgCode = orgCodeClaim.value as? String {
            let org = Organization(code: orgCode)
            return org
        }
        return nil
    }
    
    public func getUserOrganizations() -> UserOrganizations? {
        if let userOrgsClaim = getClaim(forKey: ClaimKey.organisationCodes.rawValue,
                                   token: .idToken),
           let userOrgs = userOrgsClaim.value as? [String] {
            
            let orgCodes = userOrgs.map({ Organization(code: $0)})
            return UserOrganizations(orgCodes: orgCodes)
        }
        return nil
    }
    
    private func getViewController() async -> UIViewController? {
        await MainActor.run {
            let keyWindow = UIApplication.shared.connectedScenes.flatMap { ($0 as? UIWindowScene)?.windows ?? [] }
                                                                .first { $0.isKeyWindow }
            var topController = keyWindow?.rootViewController
            while let presentedViewController = topController?.presentedViewController {
                topController = presentedViewController
            }
            return topController
        }
    }
    
    /// Register a new user
    ///
    @available(*, renamed: "register")
    public func register(orgCode: String = "",
                         _ completion: @escaping (Result<Bool, Error>) -> Void) {
        Task {
            do {
                try await register(orgCode: orgCode)
                await MainActor.run(body: {
                    completion(.success(true))
                })
            } catch {
                await MainActor.run(body: {
                    completion(.failure(error))
                })
            }
        }
    }
    
    public func register(orgCode: String = "") async throws -> () {
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                guard let viewController = await self.getViewController() else {
                    continuation.resume(throwing: AuthError.notAuthenticated)
                    return
                }
                do {
                    let request = try await self.getAuthorizationRequest(signUp: true, orgCode: orgCode)
                    _ = try await self.runCurrentAuthorizationFlow(request: request, viewController: viewController)
                    continuation.resume(with: .success(()))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    /// Login an existing user
    ///
    @available(*, renamed: "login")
    public func login(orgCode: String = "",
                      _ completion: @escaping (Result<Bool, Error>) -> Void) {
        Task {
            do {
                try await login(orgCode: orgCode)
                await MainActor.run(body: {
                    completion(.success(true))
                })
            } catch {
                await MainActor.run(body: {
                    completion(.failure(error))
                })
            }
        }
    }

    public func login(orgCode: String = "") async throws -> () {
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                guard let viewController = await self.getViewController() else {
                    continuation.resume(throwing: AuthError.notAuthenticated)
                    return
                }
                do {
                    let request = try await self.getAuthorizationRequest(signUp: false, orgCode: orgCode)
                    _ = try await self.runCurrentAuthorizationFlow(request: request, viewController: viewController)
                    continuation.resume(with: .success(()))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
        
    /// Register a new organization
    ///
    @available(*, renamed: "createOrg")
    public func createOrg( _ completion: @escaping (Result<Bool, Error>) -> Void) {
        Task {
            do {
                try await createOrg()
                await MainActor.run(body: {
                    completion(.success(true))
                })
            } catch {
                await MainActor.run(body: {
                    completion(.failure(error))
                })
            }
        }
    }

    public func createOrg(orgName: String = "") async throws -> () {
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                guard let viewController = await self.getViewController() else {
                    continuation.resume(throwing: AuthError.notAuthenticated)
                    return
                }
                do {
                    let request = try await self.getAuthorizationRequest(signUp: true, createOrg: true, orgName: orgName)
                    _ = try await self.runCurrentAuthorizationFlow(request: request, viewController: viewController)
                    continuation.resume(with: .success(()))
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    /// Logout the current user
    @available(*, renamed: "logout()")
    public func logout(_ completion: @escaping (_ result: Bool) -> Void) {
        Task {
            let result = await logout()
            await MainActor.run {
                completion(result)
            }
        }
    }
    
    public func logout() async -> Bool {
        // There is no logout endpoint configured; simply clear the local auth state
        let cleared = authStateRepository.clear()
        return cleared
    }
    
    /// Create an Authorization Request using the configured Issuer and Redirect URLs,
    /// and OpenIDConnect configuration discovery
    @available(*, renamed: "getAuthorizationRequest(signUp:createOrg:orgCode:usePKCE:useNonce:)")
    private func getAuthorizationRequest(signUp: Bool,
                                         createOrg: Bool = false,
                                         orgCode: String = "",
                                         usePKCE: Bool = true,
                                         useNonce: Bool = false,
                                         then completion: @escaping (Result<OIDAuthorizationRequest, Error>) -> Void) {
        Task {
            do {
                let request = try await self.getAuthorizationRequest(signUp: signUp, createOrg: createOrg, orgCode: orgCode, usePKCE: usePKCE, useNonce: useNonce)
                completion(.success(request))
            } catch {
                completion(.failure(AuthError.notAuthenticated))
            }
        }
    }
    
    private func getAuthorizationRequest(signUp: Bool,
                                         createOrg: Bool = false,
                                         orgCode: String = "",
                                         orgName: String = "",
                                         usePKCE: Bool = true,
                                         useNonce: Bool = false) async throws -> OIDAuthorizationRequest {
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                let issuerUrl = config.getIssuerUrl()
                guard let issuerUrl = issuerUrl else {
                    logger.error(message: "Failed to get issuer URL")
                    continuation.resume(throwing: AuthError.configuration)
                    return
                }
                do {
                    let result = try await discoverConfiguration(issuerUrl: issuerUrl,
                                                                 signUp: signUp,
                                                                 createOrg: createOrg,
                                                                 orgCode: orgCode,
                                                                 orgName: orgName,
                                                                 usePKCE: usePKCE,
                                                                 useNonce: useNonce)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
        }
    }
    
    private func runCurrentAuthorizationFlow(request: OIDAuthorizationRequest, viewController: UIViewController) async throws -> Bool {
        return try await withCheckedThrowingContinuation { continuation in
            Task {
                await MainActor.run {
                    currentAuthorizationFlow = OIDAuthState.authState(byPresenting: request,
                                                                      presenting: viewController,
                                                                      prefersEphemeralSession: privateAuthSession,
                                                                      callback: authorizationFlowCallback(then: { value in
                        switch value {
                        case .success:
                            continuation.resume(returning: true)
                        case .failure(let error):
                            continuation.resume(throwing: error)
                        }
                    }))
                }
            }
        }
    }
    
    private func discoverConfiguration(issuerUrl: URL,
                                              signUp: Bool,
                                              createOrg: Bool = false,
                                              orgCode: String = "",
                                              orgName: String = "",
                                              usePKCE: Bool = true,
                                              useNonce: Bool = false) async throws -> (OIDAuthorizationRequest) {
        return try await withCheckedThrowingContinuation { continuation in
            OIDAuthorizationService.discoverConfiguration(forIssuer: issuerUrl) { configuration, error in
                if let error = error {
                    self.logger.error(message: "Failed to discover OpenID configuration: \(error.localizedDescription)")
                    continuation.resume(throwing: error)
                }
                
                guard let configuration = configuration else {
                    self.logger.error(message: "Failed to discover OpenID configuration")
                    continuation.resume(throwing: AuthError.configuration)
                    return
                }
                
                let redirectUrl = self.config.getRedirectUrl()
                guard let redirectUrl = redirectUrl else {
                    self.logger.error(message: "Failed to get redirect URL")
                    continuation.resume(throwing: AuthError.configuration)
                    return
                }
                
                var additionalParameters = [
                    "start_page": signUp ? "registration" : "login",
                    // Force fresh login
                    "prompt": "login"
                ]
                
                if createOrg {
                    additionalParameters["is_create_org"] = "true"
                }
                
                if let audience = self.config.audience, !audience.isEmpty {
                   additionalParameters["audience"] = audience
                }
                
                if !orgCode.isEmpty {
                    additionalParameters["org_code"] = orgCode
                }
                
                if !orgName.isEmpty {
                    additionalParameters["org_name"] = orgName
                }
                
                // if/when the API supports nonce validation
                let codeChallengeMethod = usePKCE ? OIDOAuthorizationRequestCodeChallengeMethodS256 : nil
                let codeVerifier = usePKCE ? OIDTokenUtilities.randomURLSafeString(withSize: 32) : nil
                let codeChallenge = usePKCE && codeVerifier != nil ? OIDTokenUtilities.encodeBase64urlNoPadding(OIDTokenUtilities.sha256(codeVerifier!)) : nil
                let state = OIDTokenUtilities.randomURLSafeString(withSize: 32)
                let nonce = useNonce ? OIDTokenUtilities.randomURLSafeString(withSize: 32) : nil

                let request = OIDAuthorizationRequest(configuration: configuration,
                                                      clientId: self.config.clientId,
                                                      clientSecret: nil, // PKCE-only OAuth flow for mobile security
                                                      scope: self.config.scope,
                                                      redirectURL: redirectUrl,
                                                      responseType: OIDResponseTypeCode,
                                                      state: state,
                                                      nonce: nonce,
                                                      codeVerifier: codeVerifier,
                                                      codeChallenge: codeChallenge,
                                                      codeChallengeMethod: codeChallengeMethod,
                                                      additionalParameters: additionalParameters)
                
                continuation.resume(returning: request)
            }
        }
    }
    
    /// Callback to complete the current authorization flow
    private func authorizationFlowCallback(then completion: @escaping (Result<Bool, Error>) -> Void) -> (OIDAuthState?, Error?) -> Void {
        return { authState, error in
            if let error = error {
                self.logger.error(message: "Failed to finish authentication flow: \(error.localizedDescription)")
                _ = self.authStateRepository.clear()
                return completion(.failure(error))
            }
            
            guard let authState = authState else {
                self.logger.error(message: "Failed to get authentication state")
                _ = self.authStateRepository.clear()
                return completion(.failure(AuthError.notAuthenticated))
            }
            
            self.logger.debug(message: "Got authorization tokens. Access token: " +
                          "\(authState.lastTokenResponse?.accessToken ?? "nil")")
            
            let saved = self.authStateRepository.setState(authState)
            if !saved {
                return completion(.failure(AuthError.failedToSaveState))
            }
            
            self.currentAuthorizationFlow = nil
            completion(.success(true))
        }
    }
    
    /// Is the given error the result of user cancellation of an authorization flow
    public func isUserCancellationErrorCode(_ error: Error) -> Bool {
        let error = error as NSError
        return error.domain == OIDGeneralErrorDomain && error.code == OIDErrorCode.userCanceledAuthorizationFlow.rawValue
    }
    
    /// Perform an action, such as an API call, with a valid access token and ID token
    /// Failure to get a valid access token may require reauthentication
    @available(*, renamed: "performWithFreshTokens()")
    func performWithFreshTokens(_ action: @escaping (Result<Tokens, Error>) -> Void) {
        Task {
            do {
                if let result = try await performWithFreshTokens() {
                    action(.success(result))
                } else {
                    action(.failure(AuthError.notAuthenticated))
                }
            } catch {
                action(.failure(error))
            }
        }
    }

    func performWithFreshTokens() async throws -> Tokens? {
        guard let authState = authStateRepository.state else {
            self.logger.error(message: "Failed to get authentication state")
            return nil
        }
        
        let params = ["Kinde-SDK": "Swift/\(SDKVersion.versionString)"]
        return try await withCheckedThrowingContinuation { continuation in
            authState.performAction(freshTokens: { (accessToken, idToken, error1) in
                if let error = error1 {
                    self.logger.error(message: "Failed to get authentication tokens: \(error.localizedDescription)")
                    return continuation.resume(with: .failure(error))
                }
                
                guard let accessToken1 = accessToken else {
                    self.logger.error(message: "Failed to get access token")
                    return continuation.resume(with: .failure(AuthError.notAuthenticated))
                }
                let tokens = Tokens(accessToken: accessToken1, idToken: idToken)
                continuation.resume(with: .success(tokens))
            }, additionalRefreshParameters: params)
        }
    }
    
    /// Return the access token with auto-refresh mechanism.
    /// - Returns: Returns access token, throw error if failed to refresh which may require re-authentication.
    public func getToken() async throws -> String {
        do {
            if let tokens = try await performWithFreshTokens() {
                return tokens.accessToken
            }else {
                throw AuthError.notAuthenticated
            }
        }catch {
            throw AuthError.notAuthenticated
        }
    }
    
    public func getTokenResponse() -> OIDTokenResponse? {
        return authStateRepository.state?.lastTokenResponse
    }
}

// MARK: - Feature Flags
extension Auth {
    
    public func getFlag(code: String, defaultValue: Any? = nil, flagType: Flag.ValueType? = nil) throws -> Flag {
        return try getFlagInternal(code: code, defaultValue: defaultValue, flagType: flagType)
    }
    
    // Wrapper Methods
    
    public func getBooleanFlag(code: String, defaultValue: Bool? = nil) throws -> Bool {
        if let value = try getFlag(code: code, defaultValue: defaultValue, flagType: .bool).value as? Bool {
            return value
        }else {
            if let defaultValue = defaultValue {
                return defaultValue
            }else {
                throw FlagError.notFound
            }
        }
    }
    
    public func getStringFlag(code: String, defaultValue: String? = nil) throws -> String {
        if let value = try getFlag(code: code, defaultValue: defaultValue, flagType: .string).value as? String {
           return value
        }else{
            if let defaultValue = defaultValue {
                return defaultValue
            }else {
                throw FlagError.notFound
            }
        }
    }
    
    public func getIntegerFlag(code: String, defaultValue: Int? = nil) throws -> Int {
        if let value = try getFlag(code: code, defaultValue: defaultValue, flagType: .int).value as? Int {
            return value
        }else {
            if let defaultValue = defaultValue {
                return defaultValue
            }else {
                throw FlagError.notFound
            }
        }
    }
    
    // Internal
    
    private func getFlagInternal(code: String, defaultValue: Any?, flagType: Flag.ValueType?) throws -> Flag {
        
        guard let featureFlagsClaim = getClaim(forKey: ClaimKey.featureFlags.rawValue) else {
            throw FlagError.unknownError
        }
        
        guard let featureFlags = featureFlagsClaim.value as? [String : Any] else {
            throw FlagError.unknownError
        }
        
        if let flagData = featureFlags[code] as? [String: Any],
           let valueTypeLetter = flagData["t"] as? String,
           let actualFlagType = Flag.ValueType(rawValue: valueTypeLetter),
           let actualValue = flagData["v"] {
            
            // Value type check
            if let flagType = flagType,
                flagType != actualFlagType {
                throw FlagError.incorrectType("Flag \"\(code)\" is type \(actualFlagType.typeDescription) - requested type \(flagType.typeDescription)")
            }
            
            return Flag(code: code, type: actualFlagType, value: actualValue)
            
        }else {
            
            if let defaultValue = defaultValue {
                // This flag does not exist - default value provided
                return Flag(code: code, type: nil, value: defaultValue, isDefault: true)
            }else {
                throw FlagError.notFound
            }
        }
    }
}


extension Auth {
    /// Hide/Show message prompt in authentication sessions.
    public func enablePrivateAuthSession(_ isEnable: Bool) {
        privateAuthSession = isEnable
    }
}

extension Auth {
    private enum ClaimKey: String {
        case permissions = "permissions"
        case organisationCode = "org_code"
        case organisationCodes = "org_codes"
        case featureFlags = "feature_flags"
    }
}

public struct Flag {
    public let code: String
    public let type: ValueType?
    public let value: Any
    public let isDefault: Bool

    public init(code: String, type: ValueType?, value: Any, isDefault: Bool = false) {
        self.code = code
        self.type = type
        self.value = value
        self.isDefault = isDefault
    }
    
    public enum ValueType: String {
        case string = "s"
        case int = "i"
        case bool = "b"
        
        fileprivate var typeDescription: String {
            switch self {
            case .string: return "string"
            case .bool: return "boolean"
            case .int: return "integer"
            }
        }
    }
}

public struct Organization {
    public let code: String
}

public struct Permission {
    public let organization: Organization
    public let isGranted: Bool
}

public struct Permissions {
    public let organization: Organization
    public let permissions: [String]
}

public struct UserOrganizations {
    public let orgCodes: [Organization]
}
//
// Claims.swift
//
// Kinde SDK Claims Model
//

import Foundation

/// Represents a claim from a JWT token
public struct Claim {
    /// The name of the claim
    public let name: String
    /// The value of the claim
    public let value: Any?
    
    public init(name: String, value: Any?) {
        self.name = name
        self.value = value
    }
}

/// Represents all claims from a token
public struct Claims {
    /// Dictionary of all claims
    public let claims: [String: Any]
    
    public init(claims: [String: Any]) {
        self.claims = claims
    }
    
    /// Get a specific claim by name
    /// - Parameter name: The name of the claim to retrieve
    /// - Returns: A Claim object with the name and value, or nil if not found
    public func getClaim(name: String) -> Claim? {
        guard let value = claims[name] else {
            return nil
        }
        return Claim(name: name, value: value)
    }
    
    /// Get all claim names
    /// - Returns: Array of claim names
    public func getClaimNames() -> [String] {
        return Array(claims.keys)
    }
    
    /// Check if a claim exists
    /// - Parameter name: The name of the claim to check
    /// - Returns: True if the claim exists, false otherwise
    public func hasClaim(name: String) -> Bool {
        return claims[name] != nil
    }
    
    /// Get the count of claims
    /// - Returns: Number of claims
    public var count: Int {
        return claims.count
    }
}

/// Common claim keys used in Kinde tokens
public enum ClaimKey: String, CaseIterable {
    // Standard JWT claims
    case audience = "aud"
    case issuer = "iss"
    case subject = "sub"
    case expiration = "exp"
    case issuedAt = "iat"
    case notBefore = "nbf"
    
    // User information (typically in ID token)
    case email = "email"
    case givenName = "given_name"
    case familyName = "family_name"
    case name = "name"
    case picture = "picture"
    case emailVerified = "email_verified"
    
    // Organization information
    case organizationCode = "org_code"
    case organizationName = "org_name"
    case organizationId = "org_id"
    case organizationCodes = "org_codes"
    
    // Permissions and roles
    case permissions = "permissions"
    case roles = "roles"
    
    // Feature flags
    case featureFlags = "feature_flags"
    
    // Custom claims (prefixed with custom:)
    case customRole = "custom:role"
    case customPreferences = "custom:preferences"
    case customSettings = "custom:settings"
}

// MARK: - Claims Service

import Foundation
import os.log

/// The Kinde claims service for accessing user claims from tokens
public final class ClaimsService {
    private unowned let auth: Auth
    private let logger: LoggerProtocol
    
    init(auth: Auth, logger: LoggerProtocol) {
        self.auth = auth
        self.logger = logger
    }
    
    /// Get a specific claim from the user's tokens
    /// - Parameters:
    ///   - claimName: The name of the claim to retrieve (e.g. "aud", "given_name")
    ///   - tokenType: The type of token to get the claim from (accessToken or idToken)
    /// - Returns: A Claim object containing the claim name and value, or nil if not found
    public func getClaim(claimName: String, tokenType: TokenType = .accessToken) -> Claim? {
        guard auth.isAuthenticated() else {
            logger.debug(message: "User not authenticated, cannot retrieve claim: \(claimName)")
            return nil
        }
        
        // Validate claim name - hard check
        guard !claimName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            logger.error(message: "Invalid claim name: claim name cannot be empty or whitespace")
            return nil
        }
        
        // Validate token type - hard check like Python SDK
        let validTokenTypes: [TokenType] = [.accessToken, .idToken]
        guard validTokenTypes.contains(tokenType) else {
            logger.error(message: "Invalid token_type '\(tokenType.rawValue)'. Valid types are: \(validTokenTypes.map { $0.rawValue })")
            return nil
        }
        
        // Use the existing getClaim method from Auth
        return auth.getClaim(forKey: claimName, token: tokenType)
    }
    
    /// Get all claims from the user's tokens
    /// - Parameter tokenType: The type of token to get claims from (accessToken or idToken)
    /// - Returns: A Claims object containing all claims from the token, or empty claims if not available
    public func getAllClaims(tokenType: TokenType = .accessToken) -> Claims {
        guard auth.isAuthenticated() else {
            logger.debug(message: "User not authenticated, cannot retrieve claims")
            return Claims(claims: [:])
        }
        
        // Validate token type - hard check like Python SDK
        let validTokenTypes: [TokenType] = [.accessToken, .idToken]
        guard validTokenTypes.contains(tokenType) else {
            logger.error(message: "Invalid token_type '\(tokenType.rawValue)'. Valid types are: \(validTokenTypes.map { $0.rawValue })")
            return Claims(claims: [:])
        }
        
        let lastTokenResponse = auth.getTokenResponse()
        let tokenToParse = tokenType == .accessToken ? lastTokenResponse?.accessToken : lastTokenResponse?.idToken
        
        guard let token = tokenToParse else {
            logger.error(message: "No token available for token type: \(tokenType.rawValue)")
            return Claims(claims: [:])
        }
        
        let parsedJWT = token.parsedJWT
        
        // Hard check: Warn if no claims are available - like Python SDK
        if parsedJWT.isEmpty {
            logger.error(message: "No claims available for token type: \(tokenType.rawValue)")
        }
        
        return Claims(claims: parsedJWT as [String: Any])
    }
    
    /// Get a claim using a predefined claim key
    /// - Parameters:
    ///   - claimKey: The predefined claim key to retrieve
    ///   - tokenType: The type of token to get the claim from
    /// - Returns: A Claim object containing the claim name and value, or nil if not found
    public func getClaim(claimKey: ClaimKey, tokenType: TokenType = .accessToken) -> Claim? {
        return getClaim(claimName: claimKey.rawValue, tokenType: tokenType)
    }
    
    /// Get user information claims from the ID token
    /// - Returns: A dictionary containing user information claims
    public func getUserInfo() -> [String: Any] {
        let idTokenClaims = getAllClaims(tokenType: .idToken)
        let userInfoKeys: [ClaimKey] = [.email, .givenName, .familyName, .name, .picture, .emailVerified]
        
        var userInfo: [String: Any] = [:]
        for key in userInfoKeys {
            if let claim = idTokenClaims.getClaim(name: key.rawValue) {
                userInfo[key.rawValue] = claim.value
            }
        }
        
        return userInfo
    }
    
    /// Get organization information claims
    /// - Returns: A dictionary containing organization information claims
    public func getOrganizationInfo() -> [String: Any] {
        let accessTokenClaims = getAllClaims(tokenType: .accessToken)
        let orgKeys: [ClaimKey] = [.organizationCode, .organizationName, .organizationId, .organizationCodes]
        
        var orgInfo: [String: Any] = [:]
        for key in orgKeys {
            if let claim = accessTokenClaims.getClaim(name: key.rawValue) {
                orgInfo[key.rawValue] = claim.value
            }
        }
        
        return orgInfo
    }
    
    /// Get token validation claims (audience, issuer, expiration, etc.)
    /// - Returns: A dictionary containing token validation claims
    public func getTokenValidationInfo() -> [String: Any] {
        let accessTokenClaims = getAllClaims(tokenType: .accessToken)
        let validationKeys: [ClaimKey] = [.audience, .issuer, .subject, .expiration, .issuedAt, .notBefore]
        
        var validationInfo: [String: Any] = [:]
        for key in validationKeys {
            if let claim = accessTokenClaims.getClaim(name: key.rawValue) {
                validationInfo[key.rawValue] = claim.value
            }
        }
        
        return validationInfo
    }
    
    /// Check if a specific claim exists
    /// - Parameters:
    ///   - claimName: The name of the claim to check
    ///   - tokenType: The type of token to check
    /// - Returns: True if the claim exists, false otherwise
    public func hasClaim(claimName: String, tokenType: TokenType = .accessToken) -> Bool {
        // Validate claim name - hard check
        guard !claimName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            logger.error(message: "Invalid claim name: claim name cannot be empty or whitespace")
            return false
        }
        
        // Validate token type - hard check like Python SDK
        let validTokenTypes: [TokenType] = [.accessToken, .idToken]
        guard validTokenTypes.contains(tokenType) else {
            logger.error(message: "Invalid token_type '\(tokenType.rawValue)'. Valid types are: \(validTokenTypes.map { $0.rawValue })")
            return false
        }
        
        return getClaim(claimName: claimName, tokenType: tokenType) != nil
    }
    
    /// Check if a specific claim exists using a predefined claim key
    /// - Parameters:
    ///   - claimKey: The predefined claim key to check
    ///   - tokenType: The type of token to check
    /// - Returns: True if the claim exists, false otherwise
    public func hasClaim(claimKey: ClaimKey, tokenType: TokenType = .accessToken) -> Bool {
        return hasClaim(claimName: claimKey.rawValue, tokenType: tokenType)
    }
    
    /// Get custom claims (claims prefixed with "custom:")
    /// - Returns: A dictionary containing all custom claims
    public func getCustomClaims() -> [String: Any] {
        let accessTokenClaims = getAllClaims(tokenType: .accessToken)
        var customClaims: [String: Any] = [:]
        
        for (key, value) in accessTokenClaims.claims {
            if key.hasPrefix("custom:") {
                customClaims[key] = value
            }
        }
        
        return customClaims
    }
    
    /// Get a specific custom claim
    /// - Parameter claimName: The name of the custom claim (with or without "custom:" prefix)
    /// - Returns: A Claim object containing the claim name and value, or nil if not found
    public func getCustomClaim(claimName: String) -> Claim? {
        // Validate claim name - hard check
        guard !claimName.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty else {
            logger.error(message: "Invalid custom claim name: claim name cannot be empty or whitespace")
            return nil
        }
        
        let fullClaimName = claimName.hasPrefix("custom:") ? claimName : "custom:\(claimName)"
        return getClaim(claimName: fullClaimName, tokenType: .accessToken)
    }
}

// MARK: - Convenience Methods
extension ClaimsService {
    
    /// Get the user's email from the ID token
    /// - Returns: The user's email address, or nil if not available
    public func getEmail() -> String? {
        return getClaim(claimKey: .email, tokenType: .idToken)?.value as? String
    }
    
    /// Get the user's given name from the ID token
    /// - Returns: The user's given name, or nil if not available
    public func getGivenName() -> String? {
        return getClaim(claimKey: .givenName, tokenType: .idToken)?.value as? String
    }
    
    /// Get the user's family name from the ID token
    /// - Returns: The user's family name, or nil if not available
    public func getFamilyName() -> String? {
        return getClaim(claimKey: .familyName, tokenType: .idToken)?.value as? String
    }
    
    /// Get the user's full name from the ID token
    /// - Returns: The user's full name, or nil if not available
    public func getFullName() -> String? {
        return getClaim(claimKey: .name, tokenType: .idToken)?.value as? String
    }
    
    /// Get the user's picture URL from the ID token
    /// - Returns: The user's picture URL, or nil if not available
    public func getPicture() -> String? {
        return getClaim(claimKey: .picture, tokenType: .idToken)?.value as? String
    }
    
    /// Get the organization code from the access token
    /// - Returns: The organization code, or nil if not available
    public func getOrganizationCode() -> String? {
        return getClaim(claimKey: .organizationCode, tokenType: .accessToken)?.value as? String
    }
    
    /// Get the organization name from the access token
    /// - Returns: The organization name, or nil if not available
    public func getOrganizationName() -> String? {
        return getClaim(claimKey: .organizationName, tokenType: .accessToken)?.value as? String
    }
    
    /// Get the token audience from the access token
    /// - Returns: The token audience, or nil if not available
    public func getAudience() -> [String]? {
        return getClaim(claimKey: .audience, tokenType: .accessToken)?.value as? [String]
    }
    
    /// Get the token issuer from the access token
    /// - Returns: The token issuer, or nil if not available
    public func getIssuer() -> String? {
        return getClaim(claimKey: .issuer, tokenType: .accessToken)?.value as? String
    }
    
    /// Get the token expiration time from the access token
    /// - Returns: The token expiration time as a Date, or nil if not available
    public func getExpirationTime() -> Date? {
        guard let expValue = getClaim(claimKey: .expiration, tokenType: .accessToken)?.value else {
            return nil
        }
        
        if let expTimestamp = expValue as? TimeInterval {
            return Date(timeIntervalSince1970: expTimestamp)
        } else if let expTimestamp = expValue as? Int {
            return Date(timeIntervalSince1970: TimeInterval(expTimestamp))
        }
        
        return nil
    }
    
    /// Check if the token is expired
    /// - Returns: True if the token is expired, false otherwise
    public func isTokenExpired() -> Bool {
        guard let expirationTime = getExpirationTime() else {
            return true // If we can't determine expiration, assume it's expired
        }
        return Date() > expirationTime
    }
}
import Foundation

/// Mobile-focused entitlements and hard checks for iOS apps
/// This class provides client-side validation of user entitlements, feature flags, and hard checks
/// based on JWT token claims, following iOS mobile app best practices.
public class MobileEntitlements {
    private unowned let auth: Auth
    private let logger: LoggerProtocol
    
    public init(auth: Auth, logger: LoggerProtocol = DefaultLogger()) {
        self.auth = auth
        self.logger = logger
    }
    
    // MARK: - Entitlements (User Permissions & Capabilities)
    
    /// Get all user entitlements from token claims
    /// - Returns: Dictionary of entitlements with their values
    public func getEntitlements() -> [String: Any] {
        guard let entitlementsClaim = auth.getClaim(forKey: "entitlements"),
              let rawEntitlements = entitlementsClaim.value else {
            logger.debug(message: "No entitlements claim found in token")
            return [:]
        }
        
        // Parse entitlements from the claim
        if let claimString = rawEntitlements as? String,
           let data = claimString.data(using: .utf8),
           let entitlements = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return entitlements
        }
        
        // If already a dictionary, return it directly
        if let entitlements = rawEntitlements as? [String: Any] {
            return entitlements
        }
        
        return [:]
    }
    
    /// Check if user has a specific entitlement
    /// - Parameters:
    ///   - entitlement: The entitlement name to check
    ///   - defaultValue: Default value if entitlement not found (hard check)
    /// - Returns: The entitlement value or default value
    public func getEntitlement(entitlement: String, defaultValue: Any = false) -> Any {
        let entitlements = getEntitlements()
        
        if let value = entitlements[entitlement] {
            return value
        }
        
        // Hard check: Log when using default value
        logger.debug(message: "Entitlement '\(entitlement)' not found, using default value: \(defaultValue)")
        return defaultValue
    }
    
    /// Check if user has a boolean entitlement
    /// - Parameters:
    ///   - entitlement: The entitlement name to check
    ///   - defaultValue: Default value if entitlement not found
    /// - Returns: Boolean entitlement value
    public func getBooleanEntitlement(entitlement: String, defaultValue: Bool = false) -> Bool {
        let value = getEntitlement(entitlement: entitlement, defaultValue: defaultValue)
        
        if let boolValue = value as? Bool {
            return boolValue
        } else if let stringValue = value as? String {
            return Bool(stringValue) ?? defaultValue
        }
        
        return defaultValue
    }
    
    /// Check if user has a numeric entitlement
    /// - Parameters:
    ///   - entitlement: The entitlement name to check
    ///   - defaultValue: Default value if entitlement not found
    /// - Returns: Numeric entitlement value
    public func getNumericEntitlement(entitlement: String, defaultValue: Int = 0) -> Int {
        let value = getEntitlement(entitlement: entitlement, defaultValue: defaultValue)
        
        if let intValue = value as? Int {
            return intValue
        } else if let stringValue = value as? String {
            return Int(stringValue) ?? defaultValue
        }
        
        return defaultValue
    }
    
    /// Check if user has a string entitlement
    /// - Parameters:
    ///   - entitlement: The entitlement name to check
    ///   - defaultValue: Default value if entitlement not found
    /// - Returns: String entitlement value
    public func getStringEntitlement(entitlement: String, defaultValue: String = "") -> String {
        let value = getEntitlement(entitlement: entitlement, defaultValue: defaultValue)
        
        if let stringValue = value as? String {
            return stringValue
        } else {
            return String(describing: value)
        }
    }
    
    // MARK: - Feature Flags
    
    /// Get all feature flags from token claims
    /// - Returns: Dictionary of feature flags with their values
    public func getFeatureFlags() -> [String: Any] {
        guard let flagsClaim = auth.getClaim(forKey: "feature_flags"),
              let rawFlags = flagsClaim.value else {
            logger.debug(message: "No feature_flags claim found in token")
            return [:]
        }
        
        // Parse feature flags from the claim
        if let claimString = rawFlags as? String,
           let data = claimString.data(using: .utf8),
           let flags = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
            return flags
        }
        
        // If already a dictionary, return it directly
        if let flags = rawFlags as? [String: Any] {
            return flags
        }
        
        return [:]
    }
    
    /// Check if a feature flag is enabled
    /// - Parameters:
    ///   - flag: The feature flag name to check
    ///   - defaultValue: Default value if flag not found (hard check)
    /// - Returns: Boolean indicating if feature is enabled
    public func isFeatureEnabled(flag: String, defaultValue: Bool = false) -> Bool {
        let flags = getFeatureFlags()
        
        if let value = flags[flag] {
            if let boolValue = value as? Bool {
                return boolValue
            } else if let stringValue = value as? String {
                return Bool(stringValue) ?? defaultValue
            }
        }
        
        // Hard check: Log when using default value
        logger.debug(message: "Feature flag '\(flag)' not found, using default value: \(defaultValue)")
        return defaultValue
    }
    
    /// Get feature flag value with type safety
    /// - Parameters:
    ///   - flag: The feature flag name to check
    ///   - defaultValue: Default value if flag not found
    /// - Returns: Feature flag value
    public func getFeatureFlag<T>(flag: String, defaultValue: T) -> T {
        let flags = getFeatureFlags()
        
        if let value = flags[flag] as? T {
            return value
        }
        
        // Hard check: Log when using default value
        logger.debug(message: "Feature flag '\(flag)' not found or type mismatch, using default value: \(defaultValue)")
        return defaultValue
    }
    
    // MARK: - Hard Checks (Client-Side Validation)
    
    /// Perform a hard check with validation and fallback
    /// - Parameters:
    ///   - checkName: Name of the check being performed
    ///   - validation: Validation function that returns the result
    ///   - fallbackValue: Fallback value if validation fails
    /// - Returns: Result of validation or fallback value
    public func performHardCheck<T>(checkName: String, validation: () -> T?, fallbackValue: T) -> T {
        if let result = validation() {
            logger.debug(message: "Hard check '\(checkName)' passed with value: \(result)")
            return result
        } else {
            logger.error(message: "Hard check '\(checkName)' failed, using fallback: \(fallbackValue)")
            return fallbackValue
        }
    }
    
    /// Validate user permissions with hard check
    /// - Parameters:
    ///   - permission: Permission to validate
    ///   - fallbackAccess: Fallback access level if validation fails
    /// - Returns: Access level (true/false or specific value)
    public func validatePermission(permission: String, fallbackAccess: Bool = false) -> Bool {
        return performHardCheck(
            checkName: "permission_\(permission)",
            validation: { auth.getPermission(name: permission) != nil },
            fallbackValue: fallbackAccess
        )
    }
    
    /// Validate user role with hard check
    /// - Parameters:
    ///   - role: Role to validate
    ///   - fallbackAccess: Fallback access level if validation fails
    /// - Returns: Access level
    public func validateRole(role: String, fallbackAccess: Bool = false) -> Bool {
        return performHardCheck(
            checkName: "role_\(role)",
            validation: { 
                // Check if role exists in claims
                guard let rolesValue = auth.getClaim(forKey: "roles")?.value else {
                    return false
                }
                if let roles = rolesValue as? [String] {
                    return roles.contains(role)
                }
                if let rolesString = rolesValue as? String {
                    return rolesString.contains(role)
                }
                return false
            },
            fallbackValue: fallbackAccess
        )
    }
    
    /// Validate feature flag with hard check
    /// - Parameters:
    ///   - flag: Feature flag to validate
    ///   - fallbackEnabled: Fallback enabled state if validation fails
    /// - Returns: Feature enabled state
    public func validateFeatureFlag(flag: String, fallbackEnabled: Bool = false) -> Bool {
        return performHardCheck(
            checkName: "feature_\(flag)",
            validation: { isFeatureEnabled(flag: flag, defaultValue: fallbackEnabled) },
            fallbackValue: fallbackEnabled
        )
    }
    
    /// Validate entitlement with hard check
    /// - Parameters:
    ///   - entitlement: Entitlement to validate
    ///   - fallbackValue: Fallback value if validation fails
    /// - Returns: Entitlement value
    public func validateEntitlement<T>(entitlement: String, fallbackValue: T) -> T {
        return performHardCheck(
            checkName: "entitlement_\(entitlement)",
            validation: { getEntitlement(entitlement: entitlement, defaultValue: fallbackValue) as? T },
            fallbackValue: fallbackValue
        )
    }
    
    // MARK: - User Context Validation
    
    /// Check if user is authenticated (hard check)
    /// - Returns: Authentication status
    public func isUserAuthenticated() -> Bool {
        return performHardCheck(
            checkName: "user_authentication",
            validation: { auth.isAuthenticated() },
            fallbackValue: false
        )
    }
    
    /// Get user organization context with hard check
    /// - Returns: Organization information
    public func getUserOrganization() -> [String: Any] {
        return performHardCheck(
            checkName: "user_organization",
            validation: { 
                guard let orgCode = auth.getClaim(forKey: "org_code")?.value else { return nil }
                return ["org_code": orgCode]
            },
            fallbackValue: [:]
        )
    }
    
    /// Get user subscription tier with hard check
    /// - Returns: Subscription tier information
    public func getUserSubscriptionTier() -> String {
        return performHardCheck(
            checkName: "subscription_tier",
            validation: { 
                guard let claimValue = auth.getClaim(forKey: "subscription_tier")?.value else {
                    return nil
                }
                return claimValue as? String
            },
            fallbackValue: "free"
        )
    }
    
    // MARK: - Usage Limits (Common Mobile Entitlements)
    
    /// Check API usage limit with hard check
    /// - Parameters:
    ///   - limitType: Type of limit (e.g., "api_calls", "storage_mb")
    ///   - fallbackLimit: Fallback limit if not found
    /// - Returns: Usage limit
    public func getUsageLimit(limitType: String, fallbackLimit: Int = 1000) -> Int {
        return validateEntitlement(entitlement: "\(limitType)_limit", fallbackValue: fallbackLimit)
    }
    
    /// Check if user has premium features
    /// - Returns: Premium status
    public func hasPremiumFeatures() -> Bool {
        return validateEntitlement(entitlement: "premium_features", fallbackValue: false)
    }
    
    /// Check if user can access advanced features
    /// - Returns: Advanced access status
    public func hasAdvancedAccess() -> Bool {
        return validateEntitlement(entitlement: "advanced_access", fallbackValue: false)
    }
    
    /// Check storage limit in MB
    /// - Returns: Storage limit in megabytes
    public func getStorageLimitMB() -> Int {
        return validateEntitlement(entitlement: "storage_limit_mb", fallbackValue: 100)
    }
    
    /// Check API rate limit per hour
    /// - Returns: API calls per hour limit
    public func getAPIRateLimit() -> Int {
        return validateEntitlement(entitlement: "api_rate_limit", fallbackValue: 1000)
    }
}
