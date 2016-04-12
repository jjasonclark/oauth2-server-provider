class CreateOauthTokens < ActiveRecord::Migration
  def change
    create_table :oauth_tokens do |t|
      t.belongs_to :oauth_client, index: true, foreign_key: true, null: false
      t.datetime :expire_at, null: false
      t.string :kind, null: false
      t.string :scope
      t.timestamps
    end
  end
end
