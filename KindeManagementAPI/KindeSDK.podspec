Pod::Spec.new do |s|
  s.name = 'KindeSDK'
  s.ios.deployment_target = '13.0'
  s.version = '1.2.0'
  s.source = { :git => 'git@github.com:OpenAPITools/openapi-generator.git', :tag => 'v0.0.1' }
  s.authors = 'OpenAPI Generator'
  s.license = 'Proprietary'
  s.homepage = 'https://github.com/OpenAPITools/openapi-generator'
  s.summary = 'KindeSDK Swift SDK'
  s.source_files = 'KindeSDK/**/*.swift'
  s.dependency 'AppAuth', '>= 1.6.2'
end