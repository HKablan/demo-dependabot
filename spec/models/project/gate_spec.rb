#-- copyright
# OpenProject is an open source project management software.
# Copyright (C) the OpenProject GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License version 3.
#
# OpenProject is a fork of ChiliProject, which is a fork of Redmine. The copyright follows:
# Copyright (C) 2006-2013 Jean-Philippe Lang
# Copyright (C) 2010-2013 the ChiliProject Team
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
#
# See COPYRIGHT and LICENSE files for more details.
#++

require "rails_helper"
require "support/shared/project_life_cycle_helpers"

RSpec.describe Project::Gate do
  it_behaves_like "a Project::LifeCycleStep event"

  describe "validations" do
    it { is_expected.to validate_inclusion_of(:type).in_array(["Project::Gate"]).with_message(:must_be_a_gate) }

    it "is invalid if `end_date` is present" do
      subject.end_date = Time.zone.today

      expect(subject).not_to be_valid
      expect(subject.errors[:base])
        .to include("Cannot assign end date to a Project::Gate")
    end

    it "is valid if `end_date` is not present" do
      valid_gate = build(:project_gate, end_date: nil)
      expect(valid_gate).to be_valid
    end

    it "is invalid if type and class name do not match" do
      subject.type = "Project::Stage"
      expect(subject).not_to be_valid
      expect(subject.errors.symbols_for(:type)).to include(:type_and_class_name_mismatch)
    end
  end
end
