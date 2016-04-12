class CreateOauthClients < ActiveRecord::Migration
  def change
    create_table :oauth_clients do |t|
      t.string :name, null: false
      t.string :client_id, null: false
      t.string :client_secret, null: false
      t.string :redirect_uri
      t.timestamps
    end
  end
end
