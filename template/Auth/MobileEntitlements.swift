import Foundation

/// Mobile-focused entitlements and hard checks for iOS apps
/// This class provides client-side validation of user entitlements, feature flags, and hard checks
/// based on JWT token claims, following iOS mobile app best practices.
public class MobileEntitlements {
    private let auth: Auth
    private let logger: LoggerProtocol
    
    public init(auth: Auth, logger: LoggerProtocol = DefaultLogger()) {
        self.auth = auth
        self.logger = logger
    }
    
    // MARK: - Entitlements (User Permissions & Capabilities)
    
    /// Get all user entitlements from token claims
    /// - Returns: Dictionary of entitlements with their values
    public func getEntitlements() -> [String: Any] {
        guard let claim = auth.getClaim(forKey: "entitlements"),
              let rawValue = claim.value else {
            logger.debug(message: "No entitlements claim found in token")
            return [:]
        }
        
        // Parse entitlements from the claim
        if let entitlements = rawValue as? [String: Any] {
            return entitlements
        }
        
        if let claimString = rawValue as? String,
           let data = claimString.data(using: .utf8),
           let entitlements = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
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
        guard let claim = auth.getClaim(forKey: "feature_flags"),
              let rawValue = claim.value else {
            logger.debug(message: "No feature_flags claim found in token")
            return [:]
        }
        
        // Parse feature flags from the claim
        if let flags = rawValue as? [String: Any] {
            return flags
        }
        
        if let claimString = rawValue as? String,
           let data = claimString.data(using: .utf8),
           let flags = try? JSONSerialization.jsonObject(with: data) as? [String: Any] {
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
            validation: {
                guard let permission = auth.getPermission(name: permission) else {
                    return nil
                }
                return permission.isGranted
            },
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
                guard let claimValue = auth.getClaim(forKey: "subscription_tier")?.value else { return nil }
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
