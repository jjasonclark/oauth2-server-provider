Rails.application.routes.draw do

  namespace :oauth, module: 'oauth' do
    get :authorize, to: 'authorize#new'
    post :authorize, to: 'authorize#create'
    post :token, to: 'token#token'
    post :revoke, to: 'token#revoke'
  end

end
